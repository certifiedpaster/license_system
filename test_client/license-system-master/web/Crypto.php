<?php
include 'Config.php';

class Crypto
{
    static public function aes_encrypt($input, $key, $iv, $url_encode = false)
    {
        $command = sprintf("cd %s && ./%s -e aes -i %s --key %s --iv %s",
            escapeshellarg(Config::Encoder_Path),
            Config::Encoder_Name,
            escapeshellarg($input),
            escapeshellarg($key),
            escapeshellarg($iv)
        );
        
        if ($url_encode) {
            $command = sprintf("%s -u", $command);
        }

        return exec($command);
    }

    static public function aes_decrypt($cipher, $key, $iv)
    {
        $command = sprintf("cd %s && ./%s -d aes -i %s --key %s --iv %s",
            escapeshellarg(Config::Encoder_Path),
            Config::Encoder_Name,
            escapeshellarg($cipher),
            escapeshellarg($key),
            escapeshellarg($iv)
        );

        return exec($command);
    }

    static public function rsa_decrypt($cipher, $private_key)
    {
        $command = sprintf("cd %s && ./%s -d rsa -i %s --private %s",
           escapeshellarg(Config::Encoder_Path),
           Config::Encoder_Name,
           escapeshellarg($cipher),
           escapeshellarg($private_key)
        );

        return exec($command);
    }
}
