<?php
namespace SilverStripe\SAML\Extensions;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\LiteralField;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Group;
use SilverStripe\Core\Environment;

	class ActiveDirectoryMemberExtension extends DataExtension {

		private static $db = array (
			'silverstripeRoles' => 'Text'
		);

		private static $required_fields = array(

		);

		public function onBeforeWrite(){
			$silverstripeRoles = $this->owner->obj('silverstripeRoles')->getValue();
			
			$adminGroup = Group::get()->filter(array('Title' => 'Administrators'))->First();
			$contentEditorsGroup = Group::get()->filter(array('Title' => 'Content Authors'))->First();
			$guid = $this->owner->GUID;
			$email = $this->owner->obj('Email')->getValue();

			//If SilverStripeRoles comes through the federated request:
			if($silverstripeRoles){
				if(strpos('IMU-MD-WEB-ADMINS',$silverstripeRoles) !== false){
					$adminGroup->Members()->add($this->owner);
				}elseif(strpos('IMU-MD-WEB-EDITORS', $silverstripeRoles) !== false){
					$contentEditorsGroup->Members()->add($this->owner);
				}else{
					$adminGroup->Members()->remove($this->owner);
					$contentEditorsGroup->Members()->remove($this->owner);
				}
			}
			//If the local user doesn't have a GUID yet, look it up and set some basic attributes:
			if(!$guid){
				$userLookup = $this->lookupUser($email);
				if($userLookup){
					$this->owner->FirstName = $userLookup['firstName'];
					$this->owner->Surname = $userLookup['lastName'];
					$this->owner->GUID = $userLookup['guid'];
				}
			}
		}

		private function lookupUser($email){
			set_time_limit(30);
			$ldapserver = 'iowa.uiowa.edu';
			$ldapuser      =  Environment::getEnv('AD_SERVICEID_USER'); 
			$ldappass     = Environment::getEnv('AD_SERVICEID_PASS');
			$ldaptree    = "DC=iowa, DC=uiowa, DC=edu";

			$ldapconn = ldap_connect($ldapserver) or die("Could not connect to LDAP server.");

			if($ldapconn) {
			    // binding to ldap server
			    ldap_set_option( $ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3 );
			    ldap_set_option( $ldapconn, LDAP_OPT_REFERRALS, 0 );
			    $ldapbind = ldap_bind($ldapconn, $ldapuser, $ldappass) or die ("Error trying to bind: ".ldap_error($ldapconn));
			    // verify binding
			    if ($ldapbind) {
			    	//do stuff
						$result = ldap_search($ldapconn,$ldaptree, "uiowaADNotificationAddress=".$email, array("uiowaADNotificationAddress=","sn", "givenName", "objectGUID", "memberOf")) or die ("Error in search query: ".ldap_error($ldapconn));
						
			        	$data = ldap_get_entries($ldapconn, $result);

			        	if($data["count"] == 1){
			        		$memberGuid = $this->GUIDtoStr($data[0]["objectguid"][0]);
			        		$resultArray['guid'] = $memberGuid;
			        		$resultArray['firstName'] = $data[0]["givenname"][0];
			        		$resultArray['lastName'] = $data[0]["sn"][0];
			        		return $resultArray;
			        	}

			    } else {
			        echo "LDAP bind failed...";
			    }
			}
			// all done? clean up
			ldap_close($ldapconn);
		}

		private function GUIDtoStr($binary_guid) {
		  $unpacked = unpack('Va/v2b/n2c/Nd', $binary_guid);
		  return sprintf('%08X-%04X-%04X-%04X-%04X%08X', $unpacked['a'], $unpacked['b1'], $unpacked['b2'], $unpacked['c1'], $unpacked['c2'], $unpacked['d']);
		}

	}
