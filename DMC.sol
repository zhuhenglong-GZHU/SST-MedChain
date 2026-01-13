// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;

contract DMC {
    address public admin;
    
    mapping(string => address) public patientOwners;
    mapping(string => address) public doctorOwners;
    uint256 public requestCounter = 0;
    
    enum KeyStatus { Unused, Used, Frozen, Revoked }

    struct DelegateRequest {
        string requestId;
        string patientId;
        string doctorId;
        uint256[4] params;
        string operation;
        bytes[] accessScale;
        bool isValid;
    }
    
    struct VerifiedDelegation {
        string delegationId;
        string parentDelegationId;
        string patientId;
        string doctorId;
        bytes[] encryptedKeys;
        bytes[] accessScale;
        string operation;
        uint256 validUntil;
        bool isValid;
        mapping(bytes32 => bool) keyExists;
        mapping(bytes32 => KeyStatus) keyStatuses;
        string[] childrenDelegationIds;
    }
    
    mapping(string => DelegateRequest) public delegateRequests;
    mapping(string => VerifiedDelegation) public verifiedDelegations;
    
    event DelegateRequestAdded(string indexed requestId);
    event DelegationVerified(string indexed delegationId);
    event ReDelegationSuccess(string indexed parentDelegationId, string indexed newDelegationId, string indexed toDoctorId);
    event DelegationRevoked(string indexed delegationId, string indexed revokerId);
    event PatientRegistered(string indexed patientId, address owner);
    event DoctorRegistered(string indexed doctorId, address owner);
    event KeyUsed(string indexed delegationId, bytes32 keyHash);

    function addDelegateRequest(
        string memory patientId,
        string memory doctorId,
        uint256[4] memory params,
        string memory operation,
        bytes[] memory accessScale
    ) public returns (string memory) {
        string memory requestId = string(abi.encodePacked("REQ-", uintToString(requestCounter)));
        requestCounter++;
        
        delegateRequests[requestId] = DelegateRequest(
            requestId, 
            patientId, 
            doctorId, 
            params, 
            operation, 
            accessScale, 
            true
        );
        emit DelegateRequestAdded(requestId);
        return requestId;
    }
    
    function checkDelegationStatus(
        string memory delegationId,
        bytes memory encryptedKey
    ) public view returns (
        bool isValid,
        uint256 validUntil,
        bool keyValid,
        bytes[] memory accessScale
    ) {
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        isValid = delegation.isValid;
        validUntil = delegation.validUntil;
        accessScale = delegation.accessScale;

        if (!isValid) {
            keyValid = false;
            return (isValid, validUntil, keyValid, accessScale);
        }

        bytes32 keyHash = keccak256(encryptedKey);
        keyValid = delegation.keyExists[keyHash] && (delegation.keyStatuses[keyHash] == KeyStatus.Unused);
        return (isValid, validUntil, keyValid, accessScale);
    }
    
    function verifyDelegation(
        string memory delegationId,
        string memory patientId,
        string memory doctorId,
        bytes[] memory encryptedKeys,
        bytes[] memory accessScale,
        string memory operation,
        uint256 validUntil
    ) public {
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        delegation.delegationId = delegationId;
        delegation.patientId = patientId;
        delegation.doctorId = doctorId;
        delegation.encryptedKeys = encryptedKeys;
        delegation.accessScale = accessScale;
        delegation.operation = operation;
        delegation.validUntil = validUntil;
        delegation.isValid = true;
        
        for (uint i = 0; i < encryptedKeys.length; i++) {
            bytes32 keyHash = keccak256(encryptedKeys[i]);
            delegation.keyExists[keyHash] = true;
            delegation.keyStatuses[keyHash] = KeyStatus.Unused;
        }
        emit DelegationVerified(delegationId);
    }
    
    function markKeyAsUsed(
        string memory delegationId,
        bytes memory encryptedKey
    ) public {
        bytes32 keyHash = keccak256(encryptedKey);
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        require(delegation.isValid, "Delegation not valid");
        require(delegation.keyExists[keyHash], "Key not found");
        require(delegation.keyStatuses[keyHash] == KeyStatus.Unused, "Key not available");
        emit KeyUsed(delegationId, keyHash);
        delegation.keyStatuses[keyHash] = KeyStatus.Used;
    }
    
    function isKeyUsed(
        string memory delegationId,
        bytes memory encryptedKey
    ) public view returns (bool) {
        bytes32 keyHash = keccak256(encryptedKey);
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        return delegation.keyStatuses[keyHash] == KeyStatus.Used;
    }

    function reDelegate(
        string memory parentDelegationId,
        string memory toDoctorId,
        bytes[] memory keysToDelegate,
        bytes[] memory newAccessScale,
        string memory newOperation,
        uint256 newValidUntil
    ) public returns (string memory) {
        VerifiedDelegation storage parentDelegation = verifiedDelegations[parentDelegationId];
        require(parentDelegation.isValid, "Parent delegation invalid");
        require(newValidUntil <= parentDelegation.validUntil, "Invalid validity period");

        // Freeze parent keys
        for(uint i=0; i<keysToDelegate.length; i++) {
            bytes32 keyHash = keccak256(keysToDelegate[i]);
            require(parentDelegation.keyExists[keyHash], "Key not found in parent");
            require(parentDelegation.keyStatuses[keyHash] == KeyStatus.Unused, "Key not unused");
            parentDelegation.keyStatuses[keyHash] = KeyStatus.Frozen;
        }

        // Create new delegation
        string memory newDelegationId = string(abi.encodePacked("DEL-", uintToString(requestCounter++)));
        VerifiedDelegation storage newDelegation = verifiedDelegations[newDelegationId];
        newDelegation.delegationId = newDelegationId;
        newDelegation.parentDelegationId = parentDelegationId;
        newDelegation.patientId = parentDelegation.patientId;
        newDelegation.doctorId = toDoctorId;
        newDelegation.encryptedKeys = keysToDelegate;
        newDelegation.accessScale = newAccessScale;
        newDelegation.operation = newOperation;
        newDelegation.validUntil = newValidUntil;
        newDelegation.isValid = true;

        for(uint i=0; i<keysToDelegate.length; i++) {
            bytes32 keyHash = keccak256(keysToDelegate[i]);
            newDelegation.keyExists[keyHash] = true;
            newDelegation.keyStatuses[keyHash] = KeyStatus.Unused;
        }

        parentDelegation.childrenDelegationIds.push(newDelegationId);
        emit ReDelegationSuccess(parentDelegationId, newDelegationId, toDoctorId);
        return newDelegationId;
    }

    function revokeDelegation(string memory delegationId, string memory revokerId) public {
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        require(delegation.isValid, "Delegation already invalid");
        
        // Check if revoker is parent doctor or patient (simplified check, real logic in RDC)
        // Here we just execute the logic
        
        delegation.isValid = false;
        
        // Refund or Consume parent keys
        if (bytes(delegation.parentDelegationId).length > 0) {
            VerifiedDelegation storage parent = verifiedDelegations[delegation.parentDelegationId];
            for(uint i=0; i<delegation.encryptedKeys.length; i++) {
                bytes32 keyHash = keccak256(delegation.encryptedKeys[i]);
                KeyStatus childStatus = delegation.keyStatuses[keyHash];
                
                if (childStatus == KeyStatus.Unused) {
                    // Refund
                    if (parent.keyStatuses[keyHash] == KeyStatus.Frozen) {
                        parent.keyStatuses[keyHash] = KeyStatus.Unused;
                    }
                } else if (childStatus == KeyStatus.Used) {
                    // Consume
                    if (parent.keyStatuses[keyHash] == KeyStatus.Frozen) {
                        parent.keyStatuses[keyHash] = KeyStatus.Used;
                    }
                } else if (childStatus == KeyStatus.Frozen) {
                    // Recursive revocation needed for children of this delegation
                    // Since we marked delegation.isValid = false, children are effectively cut off
                    // But we should recursively process them to update states if needed
                    // For simplicity in this iteration, we just mark parent as Used to be safe or Unused?
                    // If it's frozen, it means it was passed down. We need to find where it went.
                    // This is the complex part. For now, let's assume if it's frozen here, we treat it as Used in parent to be safe, 
                    // OR we rely on the recursive call below.
                }
            }
        }

        // Recursive revocation for children
        for(uint i=0; i<delegation.childrenDelegationIds.length; i++) {
            revokeDelegation(delegation.childrenDelegationIds[i], revokerId);
        }

        emit DelegationRevoked(delegationId, revokerId);
    }
    
    function getDelegateRequest(string memory requestId) public view returns (
        string memory,
        string memory,
        string memory,
        uint256[4] memory,
        string memory,
        bytes[] memory,
        bool
    ) {
        DelegateRequest memory request = delegateRequests[requestId];
        return (
            request.requestId,
            request.patientId,
            request.doctorId,
            request.params,
            request.operation,
            request.accessScale,
            request.isValid
        );
    }

    function getVerifiedDelegation(string memory delegationId) public view returns (
        string memory,
        string memory,
        string memory,
        string memory,
        bytes[] memory,
        bytes[] memory,
        string memory,
        uint256,
        bool
    ) {
        VerifiedDelegation storage delegation = verifiedDelegations[delegationId];
        return (
            delegation.delegationId,
            delegation.parentDelegationId,
            delegation.patientId,
            delegation.doctorId,
            delegation.encryptedKeys,
            delegation.accessScale,
            delegation.operation,
            delegation.validUntil,
            delegation.isValid
        );
    }
    
    function uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }
}