// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;
contract SMC {
    address public admin;
    
    mapping(string => address) public doctorOwners;
    mapping(string => address) public hospitalOwners;
    
    struct SubjectAttributes {
        bytes role;
        bytes department;
        bytes[] specializations;
        uint256 licenseNumber;
        bytes[] additionalAttributes;
        bool isActive;
    }
    
    struct EnvironmentAttributes {
        uint256 timestamp;
        bytes location;
        bytes deviceType;
        bytes accessPurpose;
        bytes[] additionalEnvAttributes;
    }
    
    mapping(string => SubjectAttributes) public subjectAttributes;
    mapping(string => EnvironmentAttributes) public envAttributes;
    
    event SubAttributesUpdated(string indexed doctorId);
    event EnvAttributesUpdated(string indexed sessionId);
    event DoctorRegistered(string indexed doctorId, address owner);
    event HospitalRegistered(string indexed hospitalId, address owner);

    constructor() public {
        admin = msg.sender;
    }

    function registerDoctor(string memory doctorId, address owner) public {
        require(msg.sender == admin, "Only admin");
        doctorOwners[doctorId] = owner;
        emit DoctorRegistered(doctorId, owner);
    }

    function registerHospital(string memory hospitalId, address owner) public {
        require(msg.sender == admin, "Only admin");
        hospitalOwners[hospitalId] = owner;
        emit HospitalRegistered(hospitalId, owner);
    }

    function getDoctorOwner(string memory doctorId) external view returns (address) {
        return doctorOwners[doctorId];
    }

    function getHospitalOwner(string memory hospitalId) external view returns (address) {
        return hospitalOwners[hospitalId];
    }
    
    function setSubjectAttributes(
        string memory doctorId,
        bytes memory role,
        bytes memory department,
        bytes[] memory specializations,
        uint256 licenseNumber,
        bytes[] memory additionalAttributes,
        bool isActive
    ) public {
        subjectAttributes[doctorId] = SubjectAttributes(
            role,
            department,
            specializations,
            licenseNumber,
            additionalAttributes,
            isActive
        );
        emit SubAttributesUpdated(doctorId);
    }
    
    function setEnvAttributes(
        string memory sessionId,
        uint256 timestamp,
        bytes memory location,
        bytes memory deviceType,
        bytes memory accessPurpose,
        bytes[] memory additionalEnvAttributes
    ) public {
        envAttributes[sessionId] = EnvironmentAttributes(
            timestamp,
            location,
            deviceType,
            accessPurpose,
            additionalEnvAttributes
        );
        emit EnvAttributesUpdated(sessionId);
    }
    
    function getDoctorAttributes(string memory doctorId) public view returns (
        bytes memory,
        bytes memory,
        bytes[] memory,
        uint256,
        bytes[] memory,
        bool
    ) {
        SubjectAttributes memory attributes = subjectAttributes[doctorId];
        return (
            attributes.role,
            attributes.department,
            attributes.specializations,
            attributes.licenseNumber,
            attributes.additionalAttributes,
            attributes.isActive
        );
    }
    
    function getEnvAttributes(string memory sessionId) public view returns (
        uint256,
        bytes memory,
        bytes memory,
        bytes memory,
        bytes[] memory
    ) {
        EnvironmentAttributes memory attributes = envAttributes[sessionId];
        return (
            attributes.timestamp,
            attributes.location,
            attributes.deviceType,
            attributes.accessPurpose,
            attributes.additionalEnvAttributes
        );
    }
}
