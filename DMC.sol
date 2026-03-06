// SPDX-License-Identifier: MIT
pragma solidity ^0.6.10;
pragma experimental ABIEncoderV2;

contract DMC {
    enum TokenStatus { Unused, Used, Frozen, Revoked }
    uint256 public constant TIMESTAMP_WINDOW = 5 minutes;

    struct Policy {
        bytes32[] accessKeys;
        bytes32 operation;
        uint256 validUntil;
        uint256 times;
    }

    struct DelegationRequest {
        bytes32 did;
        string patientId;
        string doctorId;
        bytes32 R;
        bytes32 c;
        Policy policy;
        uint256 timestamp;
        bool exists;
    }

    struct VerifiedDelegation {
        string patientId;
        string doctorId;
        Policy policy;
        bool exists;
    }

    struct TokenInfo {
        TokenStatus status;
        bytes32 did;
        bytes32 bind;
    }

    mapping(bytes32 => DelegationRequest) public delegationRequests;
    mapping(bytes32 => VerifiedDelegation) public verifiedDelegations;
    mapping(bytes32 => TokenInfo) public tokens;
    mapping(bytes32 => bytes32[]) public roots;
    mapping(bytes32 => bytes32) public prevDid;

    event DelegationRequested(bytes32 indexed did, string patientId, string doctorId);
    event DelegationVerified(bytes32 indexed did, uint256 tokenCount);
    event TokenConsumed(bytes32 indexed tid, bytes32 indexed did);
    event TokenBound(bytes32 indexed tid, bytes32 indexed bind);
    event ReDelegated(bytes32 indexed parentDid, bytes32 indexed newDid, string toDoctorId, uint256 tokenCount);
    event Revoked(bytes32 indexed rootDid, uint256 tokenCount);

    function createDelegationRequest(
        string memory patientId,
        string memory doctorId,
        bytes32 R,
        bytes32 c,
        bytes32[] memory accessKeys,
        bytes32 operation,
        uint256 validUntil,
        uint256 times,
        uint256 timestamp,
        address patientOwner,
        bytes memory sigPatient
    ) public returns (bytes32 did) {
        if (timestamp >= block.timestamp) {
            require(timestamp - block.timestamp <= TIMESTAMP_WINDOW, "Timestamp out of window");
        } else {
            require(block.timestamp - timestamp <= TIMESTAMP_WINDOW, "Timestamp out of window");
        }
        did = sha256(abi.encode(patientId, doctorId, R, c, accessKeys, operation, validUntil, times, timestamp));
        bytes32 msgHash = keccak256(abi.encodePacked(did));
        require(_verify(patientOwner, msgHash, sigPatient), "Patient signature invalid");
        DelegationRequest storage req = delegationRequests[did];
        require(!req.exists, "Delegation exists");
        req.did = did;
        req.patientId = patientId;
        req.doctorId = doctorId;
        req.R = R;
        req.c = c;
        req.policy = Policy(accessKeys, operation, validUntil, times);
        req.timestamp = timestamp;
        req.exists = true;
        emit DelegationRequested(did, patientId, doctorId);
        return did;
    }

    function verifyDelegation(
        bytes32 did,
        string memory doctorId,
        bytes32 NPrime,
        bytes[] memory wList,
        address doctorOwner,
        bytes memory sigDoctor
    ) public {
        DelegationRequest storage req = delegationRequests[did];
        require(req.exists, "Delegation request missing");
        require(_eqString(req.doctorId, doctorId), "Doctor mismatch");
        require(sha256(abi.encodePacked(NPrime)) == req.c, "Commitment check failed");
        require(wList.length <= req.policy.times, "Too many tokens");

        bytes32 msgHash = keccak256(abi.encode(did, NPrime, wList));
        require(_verify(doctorOwner, msgHash, sigDoctor), "Doctor signature invalid");

        VerifiedDelegation storage vd = verifiedDelegations[did];
        require(!vd.exists, "Delegation already verified");
        vd.patientId = req.patientId;
        vd.doctorId = req.doctorId;
        vd.policy = req.policy;
        vd.exists = true;

        for (uint256 i = 0; i < wList.length; i++) {
            bytes32 tid = sha256(wList[i]);
            require(tokens[tid].did == bytes32(0), "Token already registered");
            tokens[tid] = TokenInfo(TokenStatus.Unused, did, bytes32(0));
            roots[did].push(tid);
        }

        emit DelegationVerified(did, wList.length);
    }

    function consumeToken(
        bytes memory w,
        string memory patientId,
        bytes32 accessKey,
        bytes32 operation,
        string memory hospitalId,
        string memory ownerDoctorId,
        address owner,
        bytes memory sigOwner
    ) public returns (bytes32 tid, bytes32 did) {
        tid = sha256(w);
        TokenInfo storage t = tokens[tid];
        require(t.status == TokenStatus.Unused, "Token not usable");
        did = t.did;
        VerifiedDelegation storage vd = verifiedDelegations[did];
        require(vd.exists, "Delegation missing");
        require(_eqString(vd.patientId, patientId), "Patient mismatch");
        require(_eqString(vd.doctorId, ownerDoctorId), "Owner mismatch");
        require(vd.policy.validUntil >= block.timestamp, "Delegation expired");
        require(_policyAllows(vd.policy, accessKey, operation), "Policy mismatch");

        bytes32 msgHash = keccak256(abi.encodePacked(w, patientId, accessKey, operation, hospitalId));
        require(_verify(owner, msgHash, sigOwner), "Owner signature invalid");

        t.status = TokenStatus.Used;
        emit TokenConsumed(tid, did);
        return (tid, did);
    }

    function setBind(bytes32 tid, bytes32 bind) public {
        TokenInfo storage t = tokens[tid];
        require(t.status == TokenStatus.Used, "Token not consumed");
        t.bind = bind;
        emit TokenBound(tid, bind);
    }

    function verifyBind(bytes32 tid, bytes32 bind) external view returns (bool) {
        TokenInfo storage t = tokens[tid];
        return t.status == TokenStatus.Used && t.bind == bind;
    }

    function reDelegate(
        bytes32 parentDid,
        string memory fromDoctorId,
        string memory toDoctorId,
        bytes32[] memory tids,
        bytes32[] memory newAccessKeys,
        bytes32 newOperation,
        uint256 newValidUntil,
        uint256 timestamp,
        address fromDoctorOwner,
        bytes memory sigFromDoctor
    ) public returns (bytes32 newDid) {
        VerifiedDelegation storage parent = verifiedDelegations[parentDid];
        require(parent.exists, "Parent delegation missing");
        require(_eqString(parent.doctorId, fromDoctorId), "Not authorized");
        require(newValidUntil <= parent.policy.validUntil, "Validity exceeds parent");
        require(_policySubset(parent.policy, newAccessKeys, newOperation), "Policy not subset");

        bytes32 msgHash = keccak256(abi.encode(parentDid, toDoctorId, tids, newAccessKeys, newOperation, newValidUntil, timestamp));
        require(_verify(fromDoctorOwner, msgHash, sigFromDoctor), "Delegator signature invalid");

        newDid = sha256(abi.encode(parentDid, toDoctorId, tids, newAccessKeys, newOperation, newValidUntil, timestamp));
        require(!verifiedDelegations[newDid].exists, "Delegation exists");
        prevDid[newDid] = parentDid;
        verifiedDelegations[newDid] = VerifiedDelegation(parent.patientId, toDoctorId, Policy(newAccessKeys, newOperation, newValidUntil, uint256(tids.length)), true);

        for (uint256 i = 0; i < tids.length; i++) {
            TokenInfo storage t = tokens[tids[i]];
            require(t.did == parentDid, "Token not in parent");
            require(t.status == TokenStatus.Unused, "Token not unused");
            t.status = TokenStatus.Frozen;
            t.did = newDid;
            t.status = TokenStatus.Unused;
        }

        emit ReDelegated(parentDid, newDid, toDoctorId, tids.length);
        return newDid;
    }

    function rollbackToParent(
        bytes32 did,
        bytes32[] memory tids,
        string memory delegatorDoctorId,
        address delegatorOwner,
        bytes memory sigDelegator
    ) public {
        bytes32 parentDid = prevDid[did];
        require(parentDid != bytes32(0), "No parent");
        require(_eqString(verifiedDelegations[parentDid].doctorId, delegatorDoctorId), "Not authorized");
        bytes32 msgHash = keccak256(abi.encode(did, tids));
        require(_verify(delegatorOwner, msgHash, sigDelegator), "Signature invalid");

        for (uint256 i = 0; i < tids.length; i++) {
            TokenInfo storage t = tokens[tids[i]];
            require(t.did == did, "Token not in delegation");
            require(t.status == TokenStatus.Unused || t.status == TokenStatus.Frozen, "Token not recoverable");
            t.did = parentDid;
        }
    }

    function revokeRoot(
        bytes32 rootDid,
        address patientOwner,
        bytes memory sigPatient
    ) public {
        bytes32 msgHash = keccak256(abi.encodePacked(rootDid));
        require(_verify(patientOwner, msgHash, sigPatient), "Signature invalid");
        bytes32[] storage tids = roots[rootDid];
        for (uint256 i = 0; i < tids.length; i++) {
            TokenInfo storage t = tokens[tids[i]];
            if (t.status == TokenStatus.Unused || t.status == TokenStatus.Frozen) {
                t.status = TokenStatus.Revoked;
            }
        }
        emit Revoked(rootDid, tids.length);
    }

    function getVerifiedParties(bytes32 did) external view returns (string memory patientId, string memory doctorId, bool exists) {
        VerifiedDelegation storage vd = verifiedDelegations[did];
        return (vd.patientId, vd.doctorId, vd.exists);
    }

    function getRootTokenCount(bytes32 rootDid) external view returns (uint256) {
        return roots[rootDid].length;
    }

    function _policyAllows(Policy storage p, bytes32 accessKey, bytes32 operation) internal view returns (bool) {
        bool keyOk = false;
        for (uint256 i = 0; i < p.accessKeys.length; i++) {
            if (p.accessKeys[i] == accessKey) {
                keyOk = true;
                break;
            }
        }
        if (!keyOk) return false;
        if (p.operation == bytes32(0)) return true;
        return p.operation == operation;
    }

    function _policySubset(Policy storage parent, bytes32[] memory childKeys, bytes32 childOp) internal view returns (bool) {
        if (parent.operation != bytes32(0) && parent.operation != childOp) return false;
        for (uint256 i = 0; i < childKeys.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < parent.accessKeys.length; j++) {
                if (parent.accessKeys[j] == childKeys[i]) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }

    function _verify(address signer, bytes32 msgHash, bytes memory signature) internal pure returns (bool) {
        if (signer == address(0)) return false;
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = _splitSig(signature);
        address recovered = ecrecover(ethHash, v, r, s);
        return recovered == signer;
    }

    function _splitSig(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "Bad signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
    }

    function _eqString(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
}
