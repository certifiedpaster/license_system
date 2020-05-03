<?php
include 'Crypto.php';

class Database
{
    private $m_Database = null;

    static public function build_hwid_hash($username, $cpu, $computer_name, $physical_hdd_serial)
    {
        if (!isset($username) ||
            !isset($cpu) ||
            !isset($computer_name) ||
            !isset($physical_hdd_serial)) {
            return false;
        }

        return sha1(sprintf("%s-%s-%s-%s",
            hash("sha256", $username),
            hash("sha256", $physical_hdd_serial),
            hash("sha256", $computer_name),
            hash("sha256", $cpu
            )));
    }

    public function connect()
    {
        $this->m_Database = new mysqli(Config::MySQL_Hostname,
            Config::MySQL_Username,
            Config::MySQL_Password,
            Config::MySQL_Database
        );
        if (mysqli_connect_errno() != 0) {
            $this->m_Database->close();
            unset($this->m_Database);
            return false;
        }
        return true;
    }

    public function disconnect()
    {
        if (isset($this->m_Database)) {
            $this->m_Database->close();
            unset($this->m_Database);
        }
    }

    public function register_user($username)
    {
        if (!$this->m_Database ||
            !isset($username)) {
            return false;
        }
        $user_data = $this->query_user_data($username);
        if ($user_data != null) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("INSERT INTO `userlist` VALUES (?,\"\",?,?,\"\",\"\",\"\",\"\")");
        if (!isset($sql_state)) {
            return false;
        }
        if (!$sql_state->bind_param('sii', $username, 0, 1)) {
            $sql_state->close();
            return false;
        }

        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }

    public function query_user_data($username)
    {
        if (!$this->m_Database) {
            return null;
        }

        $sql_state = $this->m_Database->prepare("SELECT `username`, `password`, `banned`, `fail_counter`, `cpu`, `computer_name`, `physical_hdd_serial`, `hwid_hash` FROM userlist WHERE `username` = ? LIMIT 1");
        if (!isset($sql_state)) {
            return null;
        }
        if (!$sql_state->bind_param('s', $username)) {
            $sql_state->close();
            return null;
        }
        if (!$sql_state->execute()) {
            $sql_state->close();
            return null;
        }
        if (!$sql_state->store_result()) {
            $sql_state->close();
            return null;
        }
        if ($sql_state->num_rows != 1) {
            $sql_state->close();
            return null;
        }

        $data = array();
        if (!$sql_state->bind_result($data["username"],
            $data["password"],
            $data["banned"],
            $data["fail_counter"],
            $data["cpu"],
            $data["computer_name"],
            $data["physical_hdd_serial"],
            $data["hwid_hash"]
        )) {
            $sql_state->close();
            return null;
        }
        if (!$sql_state->fetch()) {
            $sql_state->close();
            return null;
        }

        $sql_state->close();
        return $data;
    }

    public function ban_user($username)
    {
        if (!$this->m_Database) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `banned` = 1 WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }
        if (!$sql_state->bind_param('s', $username)) {
            $sql_state->close();
            return false;
        }

        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }

    public function unban_user($username)
    {
        if (!$this->m_Database) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `banned` = 0 WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }
        if (!$sql_state->bind_param('s', $username)) {
            $sql_state->close();
            return false;
        }

        $updated = $sql_state->execute();
        $sql_state->close();

        return $updated ? $this->reset_user_failure_counter($username) : false;
    }

    public function update_password($username, $password)
    {
        if (!$this->m_Database) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `password` = ? WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }
        if (!$sql_state->bind_param('ss', $password, $username)) {
            $sql_state->close();
            return false;
        }

        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }

    public function update_hwid($username, $cpu, $computer_name, $physical_hdd_serial)
    {
        if (!$this->m_Database ||
            !isset($username) ||
            !isset($cpu) ||
            !isset($computer_name) ||
            !isset($physical_hdd_serial)) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `cpu` = ?, `computer_name` = ?, `physical_hdd_serial` = ?, `hwid_hash` = ? WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }

        $hwid_hash = self::build_hwid_hash($username, $cpu, $computer_name, $physical_hdd_serial);
        if (!$sql_state->bind_param('sssss',
            $cpu,
            $computer_name,
            $physical_hdd_serial,
            $hwid_hash,
            $username
        )) {
            $sql_state->close();
            return false;
        }

        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }

    public function reset_user_failure_counter($username)
    {
        if (!$this->m_Database ||
            !isset($username)) {
            return false;
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `fail_counter` = 1 WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }
        if (!$sql_state->bind_param('s', $username)) {
            $sql_state->close();
            return false;
        }
        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }

    public function increment_user_failure_counter($username)
    {
        $user_data = $this->query_user_data($username);
        if (!$user_data) {
            return false;
        }

        $num_of_failures = $user_data["fail_counter"];
        if ($num_of_failures >= 3) {
            return $this->ban_user($username);
        }

        $sql_state = $this->m_Database->prepare("UPDATE `userlist` SET `fail_counter` = ? WHERE `username` = ?");
        if (!isset($sql_state)) {
            return false;
        }

        $num_of_failures++;
        if (!$sql_state->bind_param('is', $num_of_failures, $username)) {
            $sql_state->close();
            return false;
        }
        $updated = $sql_state->execute();
        $sql_state->close();
        return $updated;
    }
}
