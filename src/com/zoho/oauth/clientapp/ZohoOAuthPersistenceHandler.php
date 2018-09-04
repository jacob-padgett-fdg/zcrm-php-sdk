<?php
require_once realpath(dirname(__FILE__)."/../client/ZohoOAuthPersistenceInterface.php");
require_once realpath(dirname(__FILE__)."/../common/ZohoOAuthException.php");
require_once realpath(dirname(__FILE__)."/../common/OAuthLogger.php");

class ZohoOAuthPersistenceHandler implements ZohoOAuthPersistenceInterface
{
  public function saveOAuthData($zohoOAuthTokens)
  {
    try{
      self::deleteOAuthTokens($zohoOAuthTokens->getUserEmailId());
      $result = db_insert('zcrm_oauth')
      ->fields(array(
        "useridentifier" => $zohoOAuthTokens->getUserEmailId(),
        "accesstoken" => $zohoOAuthTokens->getAccessToken(),
        "refreshtoken" => $zohoOAuthTokens->getRefreshToken(),
        "expirytime" => $zohoOAuthTokens->getExpiryTime(),
      ))
      ->execute();
      if(!$result)
      {
        watchdog("zcrm_api", "error", "Unable to store token in database.");
      }

    }
    catch (Exception $ex)
    {
      Logger:severe("Exception occured while inserting OAuthTokens into DB(file::ZohoOAuthPersistenceHandler)({$ex->getMessage()})\n{$ex}");
    }
  }

  public function getOAuthTokens($userEmailId)
  {
    $oAuthTokens=new ZohoOAuthTokens();
    try{
      $fields = array(
        "useridentifier",
        "accesstoken",
        "refreshtoken",
        "expirytime",
      );
      $resultSet = db_select('zcrm_oauth', 'z')->
      fields('z', $fields)
      ->condition('useridentifier', $userEmailId, '=')
      ->execute()->fetchAssoc();
      if (!$resultSet) {
        OAuthLogger::severe("Getting result set failed: (" . $db_link->errno . ") " . $db_link->error);
        throw new ZohoOAuthException("No Tokens exist for the given user-identifier,Please generate and try again.");
      }else{
          $oAuthTokens->setExpiryTime($row["expirytime"]);
          $oAuthTokens->setRefreshToken($row["refreshtoken"]);
          $oAuthTokens->setAccessToken($row["accesstoken"]);
          $oAuthTokens->setUserEmailId($row["useridentifier"]);
      }
    }
    catch (Exception $ex)
    {
      OAuthLogger::severe("Exception occured while getting OAuthTokens from DB(file::ZohoOAuthPersistenceHandler)({$ex->getMessage()})\n{$ex}");
    }
    return $oAuthTokens;
  }

  public function deleteOAuthTokens($userEmailId)
  {
    try{
      db_delete('zcrm_oauth')
      ->condition('useridentifier', $userEmailId)
      ->execute();
    }
    catch (Exception $ex)
    {
      OAuthLogger::severe("Exception occured while Deleting OAuthTokens from DB(file::ZohoOAuthPersistenceHandler)({$ex->getMessage()})\n{$ex}");
    }
  }
}
?>
