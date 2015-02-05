<?php
/**
 * Copyright (c) 2014 Robin Appelman <icewind@owncloud.com>
 * This file is licensed under the Licensed under the MIT license:
 * http://opensource.org/licenses/MIT
 */

namespace Icewind\SMB;

use Icewind\SMB\Exception\ConnectionException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class RawConnection {
	/**
	 * Connection timeout in seconds
	 *
	 * @var integer
	 */
	public $timeout = 10;

	/**
	 * @var LoggerInterface $logger
	 */
	protected $logger;

	/**
	 * @var resource[] $pipes
	 *
	 * $pipes[0] holds STDIN for smbclient
	 * $pipes[1] holds STDOUT for smbclient
	 */
	private $pipes;

	/**
	 * @var resource $process
	 */
	private $process;

	/**
	 * List of created connection to be closed on shutdown by
	 * RawConnection::closeAll()
	 *
	 * @var array $connection_list
	 */
	private static $connection_list = array();

	public function __construct($command, $env = array(),
			LoggerInterface $logger = null
	) {
		$this->logger = $logger ? $logger : new NullLogger;
		$descriptorSpec = array(
			0 => array('pipe', 'r'), // child reads from stdin
			1 => array('pipe', 'w'), // child writes to stdout
			2 => array('pipe', 'w'), // child writes to stderr
			3 => array('pipe', 'r'), // child reads from fd#3
			4 => array('pipe', 'r'), // child reads from fd#4
			5 => array('pipe', 'w')  // child writes to fd#5
		);
		setlocale(LC_ALL, Server::LOCALE);
		$env = array_merge($env, array(
			'CLI_FORCE_INTERACTIVE' => 'y', // Needed or the prompt isn't displayed!!
			'LC_ALL' => Server::LOCALE,
			'LANG' => Server::LOCALE,
			'COLUMNS' => 8192 // prevent smbclient from line-wrapping it's output
		));
		$this->process = proc_open('exec ' . $command,
				$descriptorSpec, $this->pipes, '/', $env);
		if (!$this->isValid()) {
			throw new ConnectionException();
		}

		if (empty(self::$connection_list)) {
			$this->logger->debug('Registering shutdown callback.');
			register_shutdown_function('\Icewind\SMB\RawConnection::closeAll');
		}
		self::$connection_list[] = $this;
		$this->logger->debug(sprintf(
				'Created new connection (count: %d)',
				count(self::$connection_list)));

		stream_set_blocking($this->getErrorStream(), 0);
		$this->readStdErr();
	}

	/**
	 * check if the connection is still active
	 *
	 * @return bool
	 */
	public function isValid() {
		if (is_resource($this->process)) {
			$status = proc_get_status($this->process);
			return $status['running'];
		} else {
			return false;
		}
	}

	/**
	 * send input to the process
	 *
	 * @param string $input
	 * @throws Icewind\SMB\Exception\ConnectionException on write error
	 */
	public function write($input) {
		$this->logger->debug('write: ' . $input);

		$this->readStdErr();
		$len = fwrite($this->getInputStream(), $input);
		$flushed = fflush($this->getInputStream());
		$this->readStdErr();

		if ($len === false) {
			throw new ConnectionException('Stream write failed.');
		}
		if (!$flushed || $len !== strlen($input)) {
			throw new ConnectionException(sprintf(
					'Stream write failed (wrote %d of %d bytes, %s).',
					$len , strlen($input),
					$flushed ? 'flushed' : 'flush failed'));
		}
	}

	/**
	 * non-blocking read stderr of the process
	 *
	 * @return array of read lines
	 */
	public function readStdErr() {
		$buff = stream_get_contents($this->getErrorStream());
		$lines = array();
		if ($buff !== "") {
			foreach (explode("\n", $buff) as $line) {
				if (trim($line) !== '') {
					$lines[] = $line;
					$this->logger->warning('stderr: ' . $line);
				}
			}
		}
		return $lines;
	}

	/**
	 * read a line of output
	 *
	 * @throws Icewind\SMB\Exception\ConnectionException on timeout
	 * @return string
	 */
	public function readLine() {
		$fh = $this->getOutputStream();

		$buff = '';
		$start = microtime(true);
		do {
			$this->readStdErr();
			$read = array($fh);
			$write = null;
			$except = null;
			if (stream_select($read, $write, $except, $this->timeout) > 0
			) {
				$buff .= fgets($fh);
			} else {
				$this->readStdErr();
				throw new ConnectionException(
						sprintf('Read timeout [%ss]', $this->timeout));
			}
		} while (!(feof($fh) || mb_substr($buff, -1) == "\n"));
		$this->readStdErr();
		$duration = microtime(true) - $start;
		$line = trim($buff);

		$this->logger->debug(
				sprintf('read [%4.3fs] %s', $duration, $line));

		return $line;

	}

	/**
	 * get all output until the process closes
	 *
	 * @return array
	 */
	public function readAll() {
		$output = array();
		while ($line = $this->readLine()) {
			$output[] = $line;
		}
		return $output;
	}

	public function getInputStream() {
		return $this->pipes[0];
	}

	public function getOutputStream() {
		return $this->pipes[1];
	}

	public function getErrorStream() {
		return $this->pipes[2];
	}

	public function getAuthStream() {
		return $this->pipes[3];
	}

	public function getFileInputStream() {
		return $this->pipes[4];
	}

	public function getFileOutputStream() {
		return $this->pipes[5];
	}

	public function writeAuthentication($user, $password) {
		$fh = $this->getAuthStream();
		$success = false;
		$auth = ($password === false)
			? "username=$user"
			: "username=$user\npassword=$password";

		if (fwrite($fh, $auth) !== false && fflush($fh)) {
			$success = true;
		}
		fclose($fh);
		$this->readStdErr();
		return $success;
	}

	public function close($terminate = true) {
		if (!is_resource($this->process)) {
			return;
		}
		$this->readStdErr();
		foreach ($this->pipes as $fh) {
			if (is_resource($fh)) {
				fclose($fh);
			}
		}
		if ($terminate) {
			proc_terminate($this->process);
		}
		proc_close($this->process);

		$index = array_search($this, self::$connection_list);
		if ($index !== FALSE) {
			unset(self::$connection_list[$index]);
		}

		$this->logger->debug(sprintf(
				'Connection closed (remaining: %d)',
				count(self::$connection_list)));
	}

	/**
	 * Close all connections
	 *
	 * Construtor registers this function with register_shutdown_function()
	 */
	public static function closeAll() {
		foreach(self::$connection_list as &$connection) {
			if ($connection) {
				try {
					$connection->close();
				} catch (\Exception $e) {}
			}
		}
	}

	public function __destruct() {
		$this->close();
	}
}
