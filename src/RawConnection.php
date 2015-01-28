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
			register_shutdown_function('\Icewind\SMB\RawConnection::closeAll');
		}
		self::$connection_list[] = $this;
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
	 */
	public function write($input) {
		$this->logger->debug('write: ' . $input);

		$len = fwrite($this->getInputStream(), $input);
		$flushed = fflush($this->getInputStream());

		if (!$flushed || $len === false || $len !== strlen($input)) {
			throw new ConnectionException('Stream write failed.');
		}
	}

	/**
	 * read a line of output
	 *
	 * @return string
	 */
	public function readLine() {
		/*
		 * A read from sbmclient sometimes fails so many times, how many
		 * characters have been written to it. This was observed on CentOS 6
		 * smbclient version 3.6.23-12.el6.
		 * Make sure we skip these failures.
		 */
		do {
			$line = stream_get_line($this->getOutputStream(), 4086, "\n");
			$meta = stream_get_meta_data($this->getOutputStream());
			$this->logger->debug('readLine: ' . $line);
		} while ($line === false && $meta['unread_bytes'] > 0);

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
		$auth = ($password === false)
			? "username=$user"
			: "username=$user\npassword=$password";

		if (fwrite($this->getAuthStream(), $auth) === false) {
			fclose($this->getAuthStream());
			return false;
		}
		fclose($this->getAuthStream());
		return true;
	}

	public function close($terminate = true) {
		if (!is_resource($this->process)) {
			return;
		}
		if ($terminate) {
			proc_terminate($this->process);
		}
		proc_close($this->process);

		$index = array_search($this, self::$connection_list);
		if ($index !== FALSE) {
			unset(self::$connection_list[$index]);
		}
	}

	/**
	 * Close all connections
	 *
	 * Construtor registers this function with register_shutdown_function()
	 */
	public static function closeAll() {
	foreach(self::$connection_list as &$process) {
		if ($process) {
			$process->close();
			}
		}
	}

	public function __destruct() {
		$this->close();
	}
}
