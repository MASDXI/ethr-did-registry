// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import "./interfaces/IERC1056.sol";

contract EthrDIDRegistry is IERC1056 {
  mapping(address => address) public owners;
  mapping(address => mapping(bytes32 => mapping(address => uint256))) public delegates;
  mapping(address => uint256) public changed;
  mapping(address => uint256) public nonces;

  modifier onlyOwner(address identity, address actor) {
    require(actor == identityOwner(identity), "bad_actor");
    _;
  }

  function changeOwner(address identity, address actor, address newOwner) internal onlyOwner(identity, actor) {
    owners[identity] = newOwner;
    emit DIDOwnerChanged(identity, newOwner, changed[identity]);
    changed[identity] = block.number;
  }

  function changeOwner(address identity, address newOwner) public {
    changeOwner(identity, msg.sender, newOwner);
  }

  function identityOwner(address identity) public view returns (address) {
    address owner = owners[identity];
    if (owner != address(0x00)) {
      return owner;
    }
    return identity;
  }

  function checkSignature(
    address identity,
    uint8 sigV,
    bytes32 sigR,
    bytes32 sigS,
    bytes32 hashMessage
  ) internal returns (address) {
    address signer = ecrecover(hashMessage, sigV, sigR, sigS);
    require(signer == identityOwner(identity), "bad_signature");
    nonces[signer]++;
    return signer;
  }

  function validDelegate(address identity, bytes32 delegateType, address delegate) public view returns (bool) {
    uint256 validity = delegates[identity][keccak256(abi.encode(delegateType))][delegate];
    return (validity > block.timestamp);
  }

  function changeOwnerSigned(address identity, uint8 sigV, bytes32 sigR, bytes32 sigS, address newOwner) public {
    bytes32 hashMessage = keccak256(
      abi.encodePacked(
        bytes1(0x19),
        bytes1(0),
        this,
        nonces[identityOwner(identity)],
        identity,
        "changeOwner",
        newOwner
      )
    );
    changeOwner(identity, checkSignature(identity, sigV, sigR, sigS, hashMessage), newOwner);
  }

  function addDelegate(
    address identity,
    address actor,
    bytes32 delegateType,
    address delegate,
    uint256 validity
  ) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp + validity;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity) public {
    addDelegate(identity, msg.sender, delegateType, delegate, validity);
  }

  function addDelegateSigned(
    address identity,
    uint8 sigV,
    bytes32 sigR,
    bytes32 sigS,
    bytes32 delegateType,
    address delegate,
    uint256 validity
  ) public {
    bytes32 hashMessage = keccak256(
      abi.encodePacked(
        bytes1(0x19),
        bytes1(0),
        this,
        nonces[identityOwner(identity)],
        identity,
        "addDelegate",
        delegateType,
        delegate,
        validity
      )
    );
    addDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hashMessage), delegateType, delegate, validity);
  }

  function revokeDelegate(
    address identity,
    address actor,
    bytes32 delegateType,
    address delegate
  ) internal onlyOwner(identity, actor) {
    delegates[identity][keccak256(abi.encode(delegateType))][delegate] = block.timestamp;
    emit DIDDelegateChanged(identity, delegateType, delegate, block.timestamp, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeDelegate(address identity, bytes32 delegateType, address delegate) public {
    revokeDelegate(identity, msg.sender, delegateType, delegate);
  }

  function revokeDelegateSigned(
    address identity,
    uint8 sigV,
    bytes32 sigR,
    bytes32 sigS,
    bytes32 delegateType,
    address delegate
  ) public {
    bytes32 hashMessage = keccak256(
      abi.encodePacked(
        bytes1(0x19),
        bytes1(0),
        this,
        nonces[identityOwner(identity)],
        identity,
        "revokeDelegate",
        delegateType,
        delegate
      )
    );
    revokeDelegate(identity, checkSignature(identity, sigV, sigR, sigS, hashMessage), delegateType, delegate);
  }

  function setAttribute(
    address identity,
    address actor,
    bytes32 name,
    bytes memory value,
    uint256 validity
  ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, block.timestamp + validity, changed[identity]);
    changed[identity] = block.number;
  }

  function setAttribute(address identity, bytes32 name, bytes memory value, uint256 validity) public {
    setAttribute(identity, msg.sender, name, value, validity);
  }

  function setAttributeSigned(
    address identity,
    uint8 sigV,
    bytes32 sigR,
    bytes32 sigS,
    bytes32 name,
    bytes memory value,
    uint256 validity
  ) public {
    bytes32 hashMessage = keccak256(
      abi.encodePacked(
        bytes1(0x19),
        bytes1(0),
        this,
        nonces[identityOwner(identity)],
        identity,
        "setAttribute",
        name,
        value,
        validity
      )
    );
    setAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hashMessage), name, value, validity);
  }

  function revokeAttribute(
    address identity,
    address actor,
    bytes32 name,
    bytes memory value
  ) internal onlyOwner(identity, actor) {
    emit DIDAttributeChanged(identity, name, value, 0, changed[identity]);
    changed[identity] = block.number;
  }

  function revokeAttribute(address identity, bytes32 name, bytes memory value) public {
    revokeAttribute(identity, msg.sender, name, value);
  }

  function revokeAttributeSigned(
    address identity,
    uint8 sigV,
    bytes32 sigR,
    bytes32 sigS,
    bytes32 name,
    bytes memory value
  ) public {
    bytes32 hashMessage = keccak256(
      abi.encodePacked(
        bytes1(0x19),
        bytes1(0),
        this,
        nonces[identityOwner(identity)],
        identity,
        "revokeAttribute",
        name,
        value
      )
    );
    revokeAttribute(identity, checkSignature(identity, sigV, sigR, sigS, hashMessage), name, value);
  }
}
