<?php
set_time_limit(0);

include 'Database.php';
include 'Enum.php';

class Server
{
    private $m_Database = null;
    private $m_Iv = null;
    private $m_Key = null;
    private $m_Error = 0;

    function __construct()
    {
        $this->m_Database = new Database();
    }

    public function initialize()
    {
        return Config::Encoder_Path !== null &&
            Config::Encoder_Name !== null &&
            Config::MySQL_Hostname !== null &&
            Config::MySQL_Username !== null &&
            Config::MySQL_Password !== null &&
            Config::MySQL_Database !== null &&
            Config::GET_Parameter !== null &&
            Config::RSA_PrivateKey !== null &&
            $this->m_Database->connect();
    }

    public function close_connection()
    {
        $this->m_Database->disconnect();
        unset($this->m_Iv);
        unset($this->m_Key);
    }

    public function parse_top_request()
    {
        return isset($_GET[Config::GET_Parameter]) ? $_GET[Config::GET_Parameter] : false;
    }

   public function handle($client_data)
    {
        $j = json_decode(Crypto::rsa_decrypt($client_data, Config::RSA_PrivateKey));
        $this->set_aes_key_pair($j->key, $j->iv);

        $j->request = $this->aes_decrypt($j->request);
        switch ($j->request) {
            case 0:
                $this->handle_login($j);
                break;

            default:
                break;
        }

        echo Crypto::aes_encrypt(json_encode(array("code" => $this->m_Error),
            JSON_FORCE_OBJECT),
            $this->m_Key,
            $this->m_Iv
        );
    }


    private function set_aes_key_pair($key, $iv)
    {
        $this->m_Key = $key;
        $this->m_Iv = $iv;
    }

    private function aes_decrypt($cipher)
    {
        return Crypto::aes_decrypt($cipher, $this->m_Key, $this->m_Iv);
    }

    private function handle_login($j)
    {
        /// decrypt the client data
        $j->hwid->computer_name = $this->aes_decrypt($j->hwid->computer_name);
        $j->hwid->cpu = $this->aes_decrypt($j->hwid->cpu);
        $j->hwid->physical_hdd_serial = $this->aes_decrypt($j->hwid->physical_hdd_serial);
        $j->password = $this->aes_decrypt($j->password);
        $j->username = $this->aes_decrypt($j->username);

        /// be sure that all strings are valid
        if (!isset($j->hwid->computer_name) ||
            !isset($j->hwid->cpu) ||
            !isset($j->hwid->physical_hdd_serial) ||
            !isset($j->password) ||
            !isset($j->username)) {
            return $this->set_last_error(eLicenseCode::Server_FailedToEncryptData);
        }


        $user_data = $this->m_Database->query_user_data($j->username);
        if (!isset($user_data)) {
            return $this->set_last_error(eLicenseCode::InvalidUser);
        }
        /// check if the user is banned
        if ($user_data["banned"] >= 1) {
            return $this->set_last_error(eLicenseCode::Banned);
        }
        /// build the password salt bash, pro top: bcrypt ;--)
        $j->password = sha1(sprintf("%s%s", $user_data["username"], $j->password));
        if (empty($user_data["password"])) {
            /// update the client password once
            if (!$this->m_Database->update_password("ReactiioN", $j->password)) {
                return $this->set_last_error(eLicenseCode::MySQL_FailedToUpdatePassword);
            }
        } else {
            if ($j->password != $user_data["password"]) {
                /// increment user failure counter
                if (!$this->m_Database->increment_user_failure_counter($j->username)) {
                    return $this->set_last_error(eLicenseCode::MySQL_FailedToIncremetCounter);
                }
                return $this->set_last_error(eLicenseCode::InvalidPassword);
            }
        }
        /// reset the failure counter as long as the user has failed to login once or more
        if ($user_data["fail_counter"] > 1) {
            if (!$this->m_Database->reset_user_failure_counter($j->username)) {
                return $this->set_last_error(eLicenseCode::MySQL_FailedToResetCounter);
            }
        }

        ///$username, $cpu, $computer_name, $physical_hdd_serial
        $hwid_hash = Database::build_hwid_hash($user_data["username"], $j->hwid->cpu, $j->hwid->computer_name, $j->hwid->physical_hdd_serial);
        if (!isset($hwid_hash)) {
            return $this->set_last_error(eLicenseCode::FailedToBuildHwidHash);
        }
        if (empty($user_data["hwid_hash"])) {
            if (!$this->m_Database->update_hwid($user_data["username"], $j->hwid->cpu, $j->hwid->computer_name, $j->hwid->physical_hdd_serial)) {
                return $this->set_last_error(eLicenseCode::MySQL_FailedToUpdateHwid);
            }
        } else {
            if ($hwid_hash != $user_data["hwid_hash"]) {
                return $this->set_last_error(eLicenseCode::InvalidHwid);
            }
        }
        return $this->set_last_error(eLicenseCode::Valid);
    }

    private function set_last_error($error)
    {
        $this->m_Error = $error;
    }
}
