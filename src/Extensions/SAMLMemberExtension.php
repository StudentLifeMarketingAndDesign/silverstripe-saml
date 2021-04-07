<?php

namespace SilverStripe\SAML\Extensions;

use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\LiteralField;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\ORM\DataExtension;

/**
 * Class SAMLMemberExtension
 *
 * Adds mappings from IdP claim rules to SilverStripe {@link Member} fields.
 */
class SAMLMemberExtension extends DataExtension {
	/**
	 * @var array
	 */
	private static $db = [
		// Pointer to the session object held by the IdP
		'SAMLSessionIndex' => 'Varchar(255)',
		// Unique user identifier, same field is used by LDAPMemberExtension
		'GUID' => 'Varchar(50)',
	];

	/**
	 * These are used by {@link SAMLController} to map specific IdP claim rules
	 * to {@link Member} fields. Availability of these claim rules are defined
	 * on the IdP.
	 *
	 * @var array
	 * @config
	 */
	private static $claims_field_mappings = [
		'urn:oid:2.5.4.42' => 'FirstName',
		'urn:oid:2.5.4.4' => 'Surname',
		'urn:oid:0.9.2342.19200300.100.1.3' => 'Email',
		'silverstripeRoles' => 'silverstripeRoles',
	];

	public function updateValidator($validator) {

		$validator->removeRequiredField('FirstName');
	}
	/**
	 * @param FieldList $fields
	 */
	public function updateCMSFields(FieldList $fields) {

		$memberLabel = '<p class="message warning"><em>In order to give someone access to this website, please enter their <strong>firstName-lastName@uiowa.edu</strong> email address below. Be sure to add them to the appropriate group (Administrators, Content Authors, etc) in the "Groups" field.</em></p>';

		if ($this->owner->IsInDB()) {
			$fields->replaceField('FirstName', ReadonlyField::create('FirstName'));
			$fields->replaceField('Surname', ReadonlyField::create('Surname'));
		} else {
			$fields->addFieldToTab('Root', LiteralField::create('MemberAddInfo', $memberLabel), 'Email');
			$fields->removeFieldFromTab('Root', 'FirstName');
			$fields->removeFieldFromTab('Root', 'Surname');
		}

		$fields->removeFieldFromTab('Root', 'Password');
		$fields->removeFieldFromTab('Root', 'ConfirmPassword');

		$fields->replaceField('GUID', new ReadonlyField('GUID'));
		$fields->removeFieldFromTab('Root', 'SAMLSessionIndex');
		$fields->removeFieldFromTab('Root', 'silverstripeRoles');
		$fields->removeFieldFromTab('Root', 'Username');
		$fields->removeFieldFromTab('Root', 'FailedLoginCount');

		$this->owner->extend('updateCMSFieldsAfterSaml', $fields);
	}

	public function memberLoggedOut() {

	}
}
