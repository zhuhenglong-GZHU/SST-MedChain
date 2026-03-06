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
    
    event DelegationRequested(bytes32 indexed did, string indexed patientId, string indexed doctorId);
    event DelegationVerified(bytes32 indexed did, string indexed doctorId, uint256 tokenCount);
    event TokenAccessed(bytes32 indexed tid, bytes32 indexed did, string cid, bytes32 bind);
    event ReDelegated(bytes32 indexed parentDid, bytes32 indexed newDid, string indexed toDoctorId);
    event Rollback(bytes32 indexed did, uint256 tokenCount);
    event Revoked(bytes32 indexed rootDid, uint256 tokenCount);
    event SetPatientMetadata(string indexed patientId, bytes32 accessKey, string CID);
    
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
    function registerDoctor(string memory doctorId, address owner) external {
        smc.registerDoctor(doctorId, owner);
    }

    function registerHospital(string memory hospitalId, address owner) external {
        smc.registerHospital(hospitalId, owner);
    }

    function registerPatient(string memory patientId, address owner) external {
        omc.registerPatient(patientId, owner);
    }

    function createDelegationRequest(
        string memory patientId,
        string memory doctorId,
        bytes32 R,
        bytes32 c,
        bytes32[] memory accessKeys,
        string memory operation,
        uint256 validUntil,
        uint256 times,
        uint256 timestamp,
        bytes memory sigPatient
    ) external returns (bytes32 did) {
        address patientOwner = omc.getPatientOwner(patientId);
        require(patientOwner != address(0), "Patient not registered");
        did = dmc.createDelegationRequest(
            patientId,
            doctorId,
            R,
            c,
            accessKeys,
            _opHash(operation),
            validUntil,
            times,
            timestamp,
            patientOwner,
            sigPatient
        );
        emit DelegationRequested(did, patientId, doctorId);
        return did;
    }

    function verifyDelegation(
        bytes32 did,
        string memory doctorId,
        bytes32 NPrime,
        bytes[] memory wList,
        bytes memory sigDoctor
    ) external {
        address doctorOwner = smc.getDoctorOwner(doctorId);
        require(doctorOwner != address(0), "Doctor not registered");
        dmc.verifyDelegation(did, doctorId, NPrime, wList, doctorOwner, sigDoctor);
        emit DelegationVerified(did, doctorId, wList.length);
    }

    function consume(
        bytes memory w,
        string memory patientId,
        bytes32 accessKey,
        string memory operation,
        string memory hospitalId,
        string memory ownerDoctorId,
        bytes memory sigOwner
    ) external returns (string memory cid, bytes32 tid, bytes32 bind) {
        address owner = smc.getDoctorOwner(ownerDoctorId);
        require(owner != address(0), "Owner not registered");

        bytes32 opHash = _opHash(operation);
        bytes32 did;
        (tid, did) = dmc.consumeToken(w, patientId, accessKey, opHash, hospitalId, ownerDoctorId, owner, sigOwner);
        cid = omc.getPatientMetadata(patientId, accessKey);
        string[] memory cids = new string[](1);
        cids[0] = cid;
        bytes32 cidsHash = _hashCidsCanonical(cids);
        bind = sha256(abi.encode(tid, patientId, accessKey, opHash, hospitalId, cidsHash));
        dmc.setBind(tid, bind);
        emit TokenAccessed(tid, did, cid, bind);
        return (cid, tid, bind);
    }

    function targetVerify(bytes32 tid, bytes32 bind) external view returns (bool) {
        return dmc.verifyBind(tid, bind);
    }

    function reDelegate(
        bytes32 parentDid,
        string memory fromDoctorId,
        string memory toDoctorId,
        bytes32[] memory tids,
        bytes32[] memory newAccessKeys,
        string memory newOperation,
        uint256 newValidUntil,
        uint256 timestamp,
        bytes memory sigFromDoctor
    ) external returns (bytes32 newDid) {
        address fromOwner = smc.getDoctorOwner(fromDoctorId);
        require(fromOwner != address(0), "Delegator not registered");
        newDid = dmc.reDelegate(
            parentDid,
            fromDoctorId,
            toDoctorId,
            tids,
            newAccessKeys,
            _opHash(newOperation),
            newValidUntil,
            timestamp,
            fromOwner,
            sigFromDoctor
        );
        emit ReDelegated(parentDid, newDid, toDoctorId);
        return newDid;
    }

    function rollbackToParent(
        bytes32 did,
        bytes32[] memory tids,
        string memory delegatorDoctorId,
        bytes memory sigDelegator
    ) external {
        address delegatorOwner = smc.getDoctorOwner(delegatorDoctorId);
        require(delegatorOwner != address(0), "Delegator not registered");
        dmc.rollbackToParent(did, tids, delegatorDoctorId, delegatorOwner, sigDelegator);
        emit Rollback(did, tids.length);
    }

    function revokeRoot(
        bytes32 rootDid,
        string memory patientId,
        bytes memory sigPatient
    ) external {
        (string memory boundPatientId,, bool exists) = dmc.getVerifiedParties(rootDid);
        require(exists, "Root delegation missing");
        require(_eqString(boundPatientId, patientId), "Patient mismatch");
        address patientOwner = omc.getPatientOwner(patientId);
        require(patientOwner != address(0), "Patient not registered");
        dmc.revokeRoot(rootDid, patientOwner, sigPatient);
        emit Revoked(rootDid, dmc.getRootTokenCount(rootDid));
    }

    function setPatientMetadata(string memory patientId, bytes32 accessKey, string memory CID) external {
        omc.setPatientMetadata(patientId, accessKey, CID);
        emit SetPatientMetadata(patientId, accessKey, CID);
    }

    function _opHash(string memory operation) internal pure returns (bytes32) {
        if (bytes(operation).length == 0) return bytes32(0);
        return keccak256(bytes(operation));
    }

    function _eqString(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }

    function _hashCidsCanonical(string[] memory cids) internal pure returns (bytes32) {
        if (cids.length > 1) {
            for (uint256 i = 0; i < cids.length; i++) {
                for (uint256 j = i + 1; j < cids.length; j++) {
                    if (_stringLt(cids[j], cids[i])) {
                        string memory tmp = cids[i];
                        cids[i] = cids[j];
                        cids[j] = tmp;
                    }
                }
            }
        }
        return sha256(abi.encode(cids));
    }

    function _stringLt(string memory a, string memory b) internal pure returns (bool) {
        bytes memory ba = bytes(a);
        bytes memory bb = bytes(b);
        uint256 minLen = ba.length < bb.length ? ba.length : bb.length;
        for (uint256 i = 0; i < minLen; i++) {
            if (ba[i] < bb[i]) return true;
            if (ba[i] > bb[i]) return false;
        }
        return ba.length < bb.length;
    }
}
