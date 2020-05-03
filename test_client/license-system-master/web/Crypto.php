<?php
include 'Config.php';

class Crypto
{
    static public function aes_encrypt($input, $key, $iv, $url_encode = false)
    {
        $command = sprintf("cd %s && ./%s -e \"aes\" -i \"%s\" --key \"%s\" --iv \"%s\"",
            (Config::Encoder_Path),
            Config::Encoder_Name,
            ($input),
            ($key),
            ($iv)
        );

        if ($url_encode) {
            $command = sprintf("%s -u", $command);
        }

        return exec($command);

    }

    static public function aes_decrypt($cipher, $key, $iv)
    {
        $command = sprintf("cd %s && ./%s -d \"aes\" -i \"%s\" --key \"%s\" --iv \"%s\"",
            (Config::Encoder_Path),
            Config::Encoder_Name,
            ($cipher),
            ($key),
            ($iv)
        );

        return exec($command);
    }

    static public function rsa_encrypt($input, $public_key)
    {
        $command = sprintf("cd %s && ./%s -e \"rsa\" -i \"%s\" --public \"%s\"",
            escapeshellarg(Config::Encoder_Path),
            Config::Encoder_Name,
            escapeshellarg($input),
            escapeshellarg($public_key)
        );
        return exec($command);
    }

    static public function rsa_decrypt($cipher, $private_key)
    {
        $command = sprintf("cd %s && ./%s -d \"rsa\" -i \"%s\" --private \"%s\"",
            (Config::Encoder_Path),
            Config::Encoder_Name,
            ($cipher),
            ($private_key)
        );

        return exec($command);

    }

    static public function generate_aes_key_pair()
    {
        $command = sprintf("cd %s && ./%s -g",
            (Config::Encoder_Path),
            Config::Encoder_Name
        );
        exec($command);

        $keypair_file_name = sprintf("%s/keypair.txt", Config::Encoder_Path);

        $file = file_get_contents($keypair_file_name);
        if (empty($file)) {
            /// obv. can't find the keypair.txt file
            return null;
        }

        $kp = array();
        $has_key = false;
        foreach (explode("\n", $file) as $line) {
            if (empty($line)) {
                continue;
            }
            if (strpos($line, '///') !== false) {
                continue;
            }

            if (!$has_key) {
                $kp["key"] = $line;
                $has_key = true;
            } else {
                $kp["iv"] = $line;
            }
        }

        exec(sprintf("rm %s", $keypair_file_name));

        return $kp;
    }
}