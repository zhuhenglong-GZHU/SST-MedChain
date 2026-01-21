// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;

import "./SMC.sol";
import "./DMC.sol";
import "./OMC.sol";

contract RDC {
    DMC public dmc;
    SMC public smc;
    OMC public omc;
    
    address public admin;
    
    struct DoctorCache {
        bytes role;
        bytes department;
        bool isActive;
        uint256 timestamp;
    }
    
    struct PatientCache {
        bool isActive;
        uint256 timestamp;
    }
    
    mapping(string => DoctorCache) public doctorCache;
    mapping(string => PatientCache) public patientCache;
    
    
   
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event ContractCalled(string indexed contractName, string indexed functionName);
    event AccessDecision(
        string indexed patientId,
        string indexed doctorId,
        bool granted,
        string reason
    );
    event AddDelegateRequest(
        string indexed patientId,
        string indexed doctorId,
        uint256[4] params,
        string operation,
        bytes[] accessScale
    );
    event SetDoctorAttributes(
        string indexed doctorId,
        bytes role,
        bytes department,
        bytes[] specializations,
        uint256 licenseNumber,
        bytes[] additionalAttributes,
        bool isActive
    );
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
    event DoctorVerifyDelegation(
        string indexed delegationId,
        uint256 N_prime,
        bytes[] encryptedKeys
    );
    event EmergencyPauseSystem();
    event SetPatientMetadata(
        string indexed patientId,
        bytes32 accessKey,
        string CID
    );
    
    // modifier onlyAdmin() {
    //     require(msg.sender == admin, "Only admin can call this");
    //     _;
    // }
    
    constructor(
        address _dmcAddress,
        address _smcAddress,
        address _omcAddress
    ) public {
        admin = msg.sender;
        dmc = DMC(_dmcAddress);
        smc = SMC(_smcAddress);
        omc = OMC(_omcAddress);
    }
    
    function addDelegateRequest(
        string memory patientId,
        string memory doctorId,
        uint256[4] memory params,
        string memory operation,
        bytes[] memory accessScale
    ) public returns (string memory) {
        string memory requestId = dmc.addDelegateRequest(
            patientId, 
            doctorId, 
            params, 
            operation, 
            accessScale
        );
        emit AddDelegateRequest(patientId, doctorId, params, operation, accessScale);
        return requestId;
    }

    function reDelegateRequest(
        string memory parentDelegationId,
        string memory fromDoctorId,
        string memory toDoctorId,
        bytes[] memory keysToDelegate,
        bytes[] memory newAccessScale,
        string memory newOperation,
        uint256 newValidUntil
    ) public returns (string memory) {
        (,,, string memory currentDoctorId,, bytes[] memory currentAccessScale, string memory currentOperation, uint256 currentValidUntil, bool isValid) = dmc.getVerifiedDelegation(parentDelegationId);
        require(isValid, "Parent delegation invalid");
        require(keccak256(abi.encodePacked(currentDoctorId)) == keccak256(abi.encodePacked(fromDoctorId)), "Not authorized");
        
        // Check if parent operation allows re-delegation
        require(keccak256(abi.encodePacked(currentOperation)) == keccak256(abi.encodePacked("Re-delegation")) || 
                keccak256(abi.encodePacked(currentOperation)) == keccak256(abi.encodePacked("All")), "Re-delegation not allowed");

        (,,, bool toDoctorActive) = getDoctorInfo(toDoctorId);
        require(toDoctorActive, "Target doctor inactive");

        require(newValidUntil <= currentValidUntil, "Validity exceeds parent");
        
        for(uint i=0; i<newAccessScale.length; i++) {
            bool found = false;
            for(uint j=0; j<currentAccessScale.length; j++) {
                if(keccak256(newAccessScale[i]) == keccak256(currentAccessScale[j])) {
                    found = true;
                    break;
                }
            }
            require(found, "Access scale not subset");
        }

        return dmc.reDelegate(parentDelegationId, toDoctorId, keysToDelegate, newAccessScale, newOperation, newValidUntil);
    }

    function revokeDelegation(string memory delegationId, string memory revokerId) public {
        (, string memory parentDelegationId, string memory patientId, string memory doctorId,,,,,) = dmc.getVerifiedDelegation(delegationId);
        
        bool isAuthorized = false;
        if (keccak256(abi.encodePacked(revokerId)) == keccak256(abi.encodePacked(patientId))) {
            isAuthorized = true;
        } else if (bytes(parentDelegationId).length > 0) {
             (,,, string memory parentDoctorId,,,,,) = dmc.getVerifiedDelegation(parentDelegationId);
             if (keccak256(abi.encodePacked(revokerId)) == keccak256(abi.encodePacked(parentDoctorId))) {
                 isAuthorized = true;
             }
        }
        
        require(isAuthorized, "Not authorized to revoke");
        dmc.revokeDelegation(delegationId, revokerId);
    }
    
    function setDoctorAttributes(
        string memory doctorId,
        bytes memory role,
        bytes memory department,
        bytes[] memory specializations,
        uint256 licenseNumber,
        bytes[] memory additionalAttributes,
        bool isActive
    ) public {
        smc.setSubjectAttributes(
            doctorId,
            role,
            department,
            specializations,
            licenseNumber,
            additionalAttributes,
            isActive
        );
        emit SetDoctorAttributes(
            doctorId,
            role,
            department,
            specializations,
            licenseNumber,
            additionalAttributes,
            isActive
        );
    }
    
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
        omc.setPatientAttributes(
            patientId, 
            gender, 
            age, 
            medicalHistory, 
            allergies, 
            bloodType, 
            insuranceInfo, 
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
        omc.updatePatientAttributes(
            patientId, 
            gender, 
            age, 
            medicalHistory, 
            allergies, 
            bloodType, 
            insuranceInfo, 
            isActive
        );
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
    
    function deactivatePatient(string memory patientId) public {
        omc.deactivatePatient(patientId);
        emit DeactivatePatient(patientId);
    }
    
    function updateDoctorCache(string memory doctorId) public {
        (bytes memory role, bytes memory department, , , , bool isActive) = 
            smc.getDoctorAttributes(doctorId);
        
        doctorCache[doctorId] = DoctorCache({
            role: role,
            department: department,
            isActive: isActive,
            timestamp: block.timestamp
        });
    }
    
    function updatePatientCache(string memory patientId) public {
        (bool exists, bool isActive) = omc.getPatientStatus(patientId);
        patientCache[patientId] = PatientCache({
            isActive: exists && isActive,
            timestamp: block.timestamp
        });
    }
    
    function accessViaDelegation(
        string memory patientId,
        string memory delegationId,
        bytes memory encryptedKey
    ) public returns (bool granted, bytes[] memory data, string memory reason, string[] memory metadata) {
        (bool isValid, uint256 validUntil, bool keyValid, bytes[] memory accessScale) = 
            dmc.checkDelegationStatus(delegationId, encryptedKey);

        if (!isValid || validUntil < block.timestamp || !keyValid) {
            data = new bytes[](0);
            metadata = new string[](0);
            if (!isValid) {
                reason = "Delegation not valid";
            } else if (validUntil < block.timestamp) {
                reason = "Delegation expired";
            } else {
                reason = "Key not valid";
            }
            return (false, data, reason, metadata);
        }

        granted = true;
        data = accessScale;
        reason = "Access granted via delegation";
        metadata = _getMetadatas(patientId, accessScale);

        dmc.markKeyAsUsed(delegationId, encryptedKey);
        return (granted, data, reason, metadata);
    }

    function doctorVerifyDelegation(
        string memory delegationId,
        uint256 N_prime,
        bytes[] memory encryptedKeys
    ) public {
        (
            ,
            string memory patientId,
            string memory doctorId,
            uint256[4] memory params,
            string memory operation,
            bytes[] memory accessScale,
            bool isValid
        ) = dmc.getDelegateRequest(delegationId);
        
        require(isValid, "Delegation request is not valid");
        require(params[2] == uint256(keccak256(abi.encodePacked(N_prime))), "Commitment check failed");
        
        uint256 validUntil = block.timestamp + params[3];
        
        dmc.verifyDelegation(
            delegationId,
            patientId,
            doctorId,
            encryptedKeys,
            accessScale,
            operation,
            validUntil
        );
        emit DoctorVerifyDelegation(delegationId, N_prime, encryptedKeys);
    }
    
    // function emergencyPauseSystem() public onlyAdmin {
    //     emit EmergencyPauseSystem();
    // }
    
    function getDoctorInfo(string memory doctorId) public view returns (
        bytes memory role,
        bytes memory department,
        bytes[] memory specializations,
        bool isActive
    ) {
        (role, department, specializations, , , isActive) = smc.getDoctorAttributes(doctorId);
        return (role, department, specializations, isActive);
    }
    

    
    function getPatientRecordPolicy(string memory patientId) public view returns (bytes32) {
        return patientRecords[patientId].policyHash;
    }
    
    struct MedicalRecord {
        string patientId;
        bytes encryptedData;
        bytes32 policyHash;
        uint256 createdAt;
        uint256 updatedAt;
        bool isActive;
    }
    
    mapping(string => MedicalRecord) private patientRecords;
    
    function _createMedicalRecord(
        string memory patientId,
        bytes memory encryptedData,
        bytes32 policyHash
    ) private {
        patientRecords[patientId] = MedicalRecord({
            patientId: patientId,
            encryptedData: encryptedData,
            policyHash: policyHash,
            createdAt: block.timestamp,
            updatedAt: block.timestamp,
            isActive: true
        });
    }
    
    function _getMetadatas(string memory patientId, bytes[] memory accessScales) internal view returns (string[] memory) {
        string[] memory cids = new string[](accessScales.length);
        for (uint256 i = 0; i < accessScales.length; i++) {
            bytes32 accessKey = _bytesToBytes32(accessScales[i]);
            cids[i] = omc.getPatientMetadata(patientId, accessKey);
        }
        return cids;
    }
    
    function setPatientMetadata(
        string memory patientId,
        bytes32 accessKey,
        string memory CID
    ) public {
        omc.setPatientMetadata(patientId, accessKey, CID);
        emit SetPatientMetadata(patientId, accessKey, CID);
    }
    
    function _bytesToBytes32(bytes memory b) internal pure returns (bytes32) {
        require(b.length == 32, "Invalid accessKey length");
        bytes32 out;
        assembly {
            out := mload(add(b, 32))
        }
        return out;
    }

}
