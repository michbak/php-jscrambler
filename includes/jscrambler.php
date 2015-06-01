<?php
/*
 * Copyright 2013, 2013 AuditMark
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the Lesser GPL
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

class Jscrambler {

    private $access_key = null;
    private $secret_key = null;
    private $api_host = 'api.jscrambler.com';
    private $api_port = 80;
    private $api_version = 4;

    public function __construct($access_key, $secret_key, $api_host, $api_port, $api_version) {
        $this->access_key = $access_key;
        $this->secret_key = $secret_key;
        if (!empty($api_host)) {
            $this->api_host = $api_host;
        }
        if (!empty($api_port)) {
            $this->api_port = $api_port;
        }
        if (!empty($api_version)) {
            $this->api_version = $api_version;
        }
    }

    public function get($resource_path, $params = array()) {
        return $this->http_request('GET', $resource_path, $params);
    }

    public function post($resource_path, $params = array()) {
        return $this->http_request('POST', $resource_path, $params);
    }

    public function delete($resource_path, $params = array()) {
        return $this->http_request('DELETE', $resource_path, $params);
    }

    private function api_url() {
        $api_host_and_port = $this->api_host;
        if ($this->api_port != 80) {
            $api_host_and_port .= ":{$this->api_port}";
        }
        return ($this->api_port == 443 ? "https" : "http") . "://" . $api_host_and_port . "/v{$this->api_version}";
    }

    private function http_request($request_method, $resource_path, $params = null) { 
        $url = "{$this->api_url()}$resource_path";
        if ($request_method == 'POST') {
            $signed_data = $this->signed_query($request_method, $resource_path, $params);
        } else {
            $url .= "?{$this->array_to_query($this->signed_query($request_method, $resource_path, $params))}";
        }
        
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        if (isset($signed_data)) {
            $json_data = self::json_stringify($signed_data);
            $tmpfname = tempnam(sys_get_temp_dir(), 'php');
            file_put_contents($tmpfname, $json_data);
            curl_setopt($curl, CURLOPT_POSTFIELDS, 
                    array("@$tmpfname;type=application/json"));
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'POST');
            if (defined(CURLOPT_SAFE_UPLOAD)) {
                curl_setopt($curl, CURLOPT_SAFE_UPLOAD, 0);
            }
        }
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $request_method);
        curl_setopt($curl, CURLOPT_PORT, $this->api_port);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($curl, CURLOPT_TIMEOUT, 0);

        $return = curl_exec($curl);
        if (!$return) {
            var_dump(curl_getinfo($curl));
            var_dump(curl_errno($curl));
            var_dump(curl_error($curl));
        }
        if (isset($signed_data)) {
            unlink($tmpfname);
        }
        curl_close($curl);
        return $return;
    }

    private static function build_file_b64_params(& $files) {
        if (!is_array($files)) {
            $files = array($files);
        }
        foreach ($files as $index => $path) {
            if (!is_string($path) || ($data = file_get_contents($path)) === false) {
                throw new Exception("Unable to read file '$path'");
            }
            $files[$index] = array(
                'name' => basename($path),
                'b64' => base64_encode($data)
            ); 
        }
        return $files;
    }

    private function signed_query($request_method, $resource_path, $params = array(), $timestamp = null) {
        $signed_params = $this->signed_params($request_method, $resource_path, $params, $timestamp);
        return $signed_params;
    }

    private function signed_params($request_method, $resource_path, $params = array(), $timestamp = null) {
        if ($request_method == 'POST' && array_key_exists('files', $params)) {
            try {
                self::build_file_b64_params($params['files']);
            } catch (Exception $e) {
                echo $e->getFile() . "({$e->getLine()}): " . $e->getMessage() . "\nTrace:\n" . $e->getTraceAsString();
                exit;
            }
        }
        $auth_params = $params;
        $auth_params['timestamp'] = $timestamp ? $timestamp : date('c');
        $auth_params['access_key'] = $this->access_key;
        $auth_params['user_agent'] = 'PHP';
        $auth_params['signature'] = $this->generate_hmac_signature($request_method, $resource_path, $auth_params);
        return $auth_params;
    }
    
    private function generate_hmac_signature($request_method, $resource_path, $params = array()) {
        $hmac_signature_data = self::hmac_signature_data($request_method, $resource_path, $this->api_host, $params);
        $hashing_context = hash_init('sha256', HASH_HMAC, $this->secret_key);
        hash_update($hashing_context, $hmac_signature_data);
        return base64_encode(hash_final($hashing_context, true));
    }

    private function hmac_signature_data($request_method, $resource_path, $host, $params = array()) {
        return strtoupper($request_method) . ';' . strtolower($host) . ';' . $resource_path . ';' . self::url_query_string($params);
    }

    private static function url_query_string($params = array()) {
        ksort($params, SORT_STRING);
        return self::array_to_query($params);
    }

    private static function array_to_query($array) {
        $kv = array();
        foreach ($array as $key => $value) {
            if(is_array($value) || is_object($value)) {
                $value = self::json_stringify($value);
            }
            $kv[] = self::urlencode($key) . '=' . self::urlencode($value);
        }
        return implode('&', $kv);
    }

    private static function urlencode($value) {
        return str_replace("+", "%20", str_replace("%7E", "~", urlencode($value)));
    }
    
    private function json_stringify($value) {
        return json_encode($value);
    }
}
?>
