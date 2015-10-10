<?php
// php-jscrambler
// ==============
//
//     (c) 2014 "Magalhas" José Magalhães <jose.magalhaes@auditmark.com>
//     php-jscrambler can be freely distributed under the GNU Lesser General Public License.
//

require_once 'includes/jscrambler.php';
require_once 'includes/path.php';
require_once 'includes/globstar.php';

// Synchronous facade with JScrambler common operations.
class JScramblerFacade {
  // Time in seconds between each request while polling the server.
  const DELAY = 3;
  // Temporary zip file name.
  const ZIP_TMP_FILE = 'jscrambler.tmp.zip';
  // absolute path to temporary zip file
  private static $absolutePathToTemporaryZipFile = null;
  // True if no console log output is intended.
  public static $silent = false;
  // Downloads a project. It returns the content of a Zip file.
  public static function downloadCode ($client, $projectId, $sourceId = null) {
    self::pollProject($client, $projectId);
    if (!self::$silent) {
      echo "Downloading project...\n";
    }
    $path = "/code/$projectId";
    if (!empty($sourceId)) {
      $path .= "/$sourceId";
    } else {
      $path .= ".zip";
    }
    $result = $client->get($path);
    if (!empty($result->error)) {
      throw new Exception($result->message);
    }
    if (!self::$silent) {
      echo "Project downloaded\n";
    }
    return $result;
  }
  // Get information of all the client projects.
  public static function getInfo ($client) {
    $response = $client->get('/code.json');
    $result = json_decode($response);
    if (empty($result)) {
      throw new Exception('Failed to parse JSON.');
    }
    if (!empty($result->error)) {
      throw new Exception($result->message);
    }
    return $result;
  }
  // Polls a project.
  public static function pollProject ($client, $projectId) {
    if (!self::$silent) {
      echo "Polling server...\n";
    }
    while (true) {
      $response = $client->get("/code/{$projectId}.json");
      $result = json_decode($response);
      if (empty($result)) {
        throw new Exception('Failed to parse JSON.');
      }
      if (!empty($result->error)) {
        throw new Exception($result->message);
      }
      if ($result->error_id === "0") {
        break;
      }
      else if (isset($result->error_id) || isset($result->error_message)) {
        throw new Exception(sprintf("Error found.\nID: %s\nMessage: %s",
          $result->error_id, $result->error_message));
      }
      else if (!isset($result->id) || isset($result->error)) {
        throw new Exception(sprintf("Something went wrong.\n%s", $response));
      }
      sleep(self::DELAY);
    }
  }
  // Uploads a project. The generated project id can be found in the response.
  public static function uploadCode ($client, $params) {
    if (!self::$silent) {
      echo "Uploading project...\n";
    }
    // Zip all the files before uploading
    self::zipProject($params['files']);
    $params['files'] = array(self::getTemporaryZipFilePath());
    // Upload
    $response = $client->post('/code.json', $params);
    $result = json_decode($response);
    if (empty($result)) {
      throw new Exception('Failed to parse JSON.');
    }
    if (!empty($result->error)) {
      throw new Exception($result->message);
    }
    if (!self::$silent) {
      echo "Project uploaded\n";
    }
    return $result;
  }
  // Deletes a project.
  public static function deleteCode ($client, $projectId) {
    if (!self::$silent) {
      echo "Deleting project...\n";
    }
    $response = $client->delete("/code/{$projectId}.zip");
    $result = json_decode($response);
    if (empty($result)) {
      throw new Exception('Failed to parse JSON.');
    }
    if (!empty($result->error)) {
      throw new Exception($result->message);
    }
    if (!self::$silent) {
      echo "Project deleted";
    }
    return $result;
  }
  // Common operation sequence intended when using the client. First it
  // uploads a project, then it polls the server to download and unzip the
  // project into a folder.
  public static function process ($configPathOrObject) {
    $config = self::parseConfig($configPathOrObject);
    // Check if keys were provided by the configuration file
    if (empty($config->keys) || empty($config->keys->accessKey) || empty($config->keys->secretKey)) {
      throw new Exception('Access key and secret key must be provided in the configuration file.');
    }
    $accessKey = $config->keys->accessKey;
    $secretKey = $config->keys->secretKey;
    // Check if host was provided and assign it to a variable
    if (!empty($config->host)) {
      $host = $config->host;
    } else {
      $host = null;
    }
    // Check if port was provided and assign it to a variable
    if (!empty($config->port)) {
      $port = $config->port;
    } else {
      $port = null;
    }
    // Check if the api version was provided and assign it to a variable
    if (!empty($config->apiVersion)) {
      $apiVersion = $config->apiVersion;
    } else {
      $apiVersion = null;
    }
    // Instance a JScrambler client
    $client = new Jscrambler($accessKey, $secretKey, $host, $port, $apiVersion);
    // Check for source files and add them to the parameters
    if (empty($config->filesSrc)) {
      throw new Exception('Source files must be provided.');
    }
    // Check if output directory was provided
    if (empty($config->filesDest)) {
      throw new Exception('Output directory must be provided.');
    }
    $dest = $config->filesDest;
    $files = $config->filesSrc;
    $filesSrc = array();
    for ($i = 0, $l = count($files); $i < $l; ++$i) {
      $filesSrc = array_merge(globstar($files[$i]), $filesSrc);
    }
    // Prepare object to post
    // Check if params were provided and assign them to a variable
    if (!empty($config->params)) {
      $params = get_object_vars($config->params);
    } else {
      $params = array();
    }
    $params['files'] = $filesSrc;
    // Send the project to the JScrambler API
    $projectId = self::uploadCode($client, $params)->id;
    // Clean the temporary zip file
    self::cleanZipFile();
    // Download the project and unzip it
    $zipContent = self::downloadCode($client, $projectId);
    if (!self::$silent) {
      echo "Writing...\n";
    }
    self::unzipProject($zipContent, $dest);
    if (!self::$silent) {
      echo "Written\n";
    }
    if (isset($config->deleteProject) && $config->deleteProject) {
      self::deleteCode($client, $projectId);
    }
  }
  // Parses a configuration file or object.
  protected static function parseConfig ($configPathOrObject) {
    if (is_string($configPathOrObject)) {
      // Get the contents from the configuration file
      $configContent = file_get_contents($configPathOrObject);
      if ($configContent === false) {
        throw new Exception(sprintf('%s configuration file not found.', $configPathOrObject));
      }
      // Parse JSON
      $config = json_decode($configContent);
      if (empty($config)) {
        throw new Exception(sprintf('Failed to decode %s configuration file.', $configPathOrObject));
      }
    } else {
      $config = $configPathOrObject;
    }
    return $config;
  }
  // Cleans the temporary zip file.
  protected static function cleanZipFile () {
    unlink(self::getTemporaryZipFilePath());
  }
  // Zips a project to a temporary file.
  protected static function zipProject ($files) {
    $hasFiles = false;
    $temporaryZipFile = self::getTemporaryZipFilePath();
    if (count($files) === 1 && '.zip' === substr($files[0], -4, 4)) {
      $hasFiles = true;
      copy($files[0], $temporaryZipFile);
    } else {
      $zip = new ZipArchive();
      $zip->open($temporaryZipFile, ZipArchive::CREATE);
      foreach ($files as $file) {
        if (!$hasFiles && is_file($file)) {
          $hasFiles = true;
        }
        $file = normalize_path($file);
        if (strpos($file, '../') === 0) {
          $file = realpath($file);
        }
        $zip->addFile($file);
      }
    }
    if (!$hasFiles) {
      throw new Exception('No source files found. If you intend to send a whole directory sufix your path with "**" (e.g. ./my-directory/**)');
    }
  }
  // Unzips a project into the given destination.
  public static function unzipProject ($zipContent, $dest) {
    $zip = new ZipArchive();
    $temporaryZipFilePath = self::getTemporaryZipFilePath();
    file_put_contents($temporaryZipFilePath, $zipContent);
    $zip->open($temporaryZipFilePath);
    $zip->extractTo($dest);
    self::cleanZipFile();
  }
  // returns a temporary zip file path using the OS defined temp dir
  private static function getTemporaryZipFilePath(){
    if(is_null(self::$absolutePathToTemporaryZipFile)){
      self::$absolutePathToTemporaryZipFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . self::ZIP_TMP_FILE;
    }
    return self::$absolutePathToTemporaryZipFile;
  }
}
