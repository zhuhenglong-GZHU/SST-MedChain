// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;
contract OMC {
    address public admin;
    
    struct PatientAttributes {
        string patientId;
        bytes gender;
        uint256 age;
        bytes[] medicalHistory;
        bytes[] allergies;
        bytes bloodType;
        bytes insuranceInfo;
        uint256 createdAt;
        uint256 updatedAt;
        bool isActive;
    }
    
    struct PatientMetadata {
        string CID;
    }
    
    mapping(string => PatientAttributes) public patientAttributes;
    mapping(string => mapping(bytes32 => PatientMetadata)) public patientMetadata;
    
    event PatientUpdated(string indexed patientId);
    event SetPatientAttributes(
        string indexed patientId,
        bytes gender,
        uint256 age,
        bytes[] medicalHistory,
        bytes[] allergies,
        bytes bloodType,
        bytes insuranceInfo,
        bool isActive
    );
    
    event UpdatePatientAttributes(
        string indexed patientId,
        bytes gender,
        uint256 age,
        bytes[] medicalHistory,
        bytes[] allergies,
        bytes bloodType,
        bytes insuranceInfo,
        bool isActive
    );
    
    event DeactivatePatient(string indexed patientId);
    
    function setPatientAttributes(
        string memory patientId,
        bytes memory gender,
        uint256 age,
        bytes[] memory medicalHistory,
        bytes[] memory allergies,
        bytes memory bloodType,
        bytes memory insuranceInfo,
        bool isActive
    ) public {
        patientAttributes[patientId] = PatientAttributes(
            patientId,
            gender,
            age,
            medicalHistory,
            allergies,
            bloodType,
            insuranceInfo,
            block.timestamp,
            block.timestamp,
            isActive
        );
        emit SetPatientAttributes(
            patientId,
            gender,
            age,
            medicalHistory,
            allergies,
            bloodType,
            insuranceInfo,
            isActive
        );
    }
    
    function updatePatientAttributes(
        string memory patientId,
        bytes memory gender,
        uint256 age,
        bytes[] memory medicalHistory,
        bytes[] memory allergies,
        bytes memory bloodType,
        bytes memory insuranceInfo,
        bool isActive
    ) public {
        PatientAttributes storage patient = patientAttributes[patientId];
        patient.gender = gender;
        patient.age = age;
        patient.medicalHistory = medicalHistory;
        patient.allergies = allergies;
        patient.bloodType = bloodType;
        patient.insuranceInfo = insuranceInfo;
        patient.isActive = isActive;
        patient.updatedAt = block.timestamp;
        emit UpdatePatientAttributes(
            patientId,
            gender,
            age,
            medicalHistory,
            allergies,
            bloodType,
            insuranceInfo,
            isActive
        );
    }
    
    function getPatientAttributes(string memory patientId) public view returns (
        string memory,
        bytes memory,
        uint256,
        bytes[] memory,
        bytes[] memory,
        bytes memory,
        bytes memory,
        uint256,
        uint256,
        bool
    ) {
        PatientAttributes memory p = patientAttributes[patientId];
        return (
            p.patientId,
            p.gender,
            p.age,
            p.medicalHistory,
            p.allergies,
            p.bloodType,
            p.insuranceInfo,
            p.createdAt,
            p.updatedAt,
            p.isActive
        );
    }

    function getPatientStatus(string memory patientId) external view returns (bool exists, bool isActive) {
        PatientAttributes memory p = patientAttributes[patientId];
        return (p.createdAt != 0, p.isActive);
    }
    
    function deactivatePatient(string memory patientId) public {
        PatientAttributes storage patient = patientAttributes[patientId];
        patient.isActive = false;
        patient.updatedAt = block.timestamp;
        emit DeactivatePatient(patientId);
    }
    
    function setPatientMetadata(
        string memory patientId,
        bytes32 accessKey,
        string memory CID
    ) public {
        patientMetadata[patientId][accessKey] = PatientMetadata({CID: CID});
    }
    
    function getPatientMetadata(
        string memory patientId,
        bytes32 accessKey
    ) public view returns (string memory) {
        return patientMetadata[patientId][accessKey].CID;
    }
}