// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SecureDataStorage {
    address public owner;

    // 授權使用者列表
    mapping(address => bool) public authorizedUsers;

    // 存儲的數據映射 (哈希值 -> IPFS CID)
    mapping(bytes32 => string) public storedData;

    // 事件，用於記錄操作
    event DataStored(bytes32 indexed dataHash, string ipfsHash, address indexed user);
    event UserAuthorized(address indexed user);
    event UserRevoked(address indexed user);

    // 合約建構函數
    constructor() {
        owner = msg.sender; // 設置合約創建者為所有者
	authorizedUsers[owner] = true; // 自動授權合約所有者
        emit UserAuthorized(owner);

    }

    // 僅限所有者修飾符
    modifier onlyOwner() {
        require(msg.sender == owner, "Only the contract owner can perform this action.");
        _;
    }

    // 僅限授權使用者修飾符
    modifier onlyAuthorized() {
        require(authorizedUsers[msg.sender], "You are not authorized to perform this action.");
        _;
    }

    // 授權使用者
    function authorizeUser(address user) public onlyOwner {
        authorizedUsers[user] = true;
        emit UserAuthorized(user); // 發出授權事件
    }

    // 撤銷授權
    function revokeUser(address user) public onlyOwner {
        authorizedUsers[user] = false;
        emit UserRevoked(user); // 發出撤銷授權事件
    }

    // 儲存資料到區塊鏈 (僅限授權使用者)
    function storeData(bytes32 dataHash, string memory ipfsHash) public onlyAuthorized {
        storedData[dataHash] = ipfsHash;
        emit DataStored(dataHash, ipfsHash, msg.sender); // 發出數據存儲事件
    }

    // 讀取存儲的IPFS哈希值
    function retrieveData(bytes32 dataHash) public view returns (string memory) {
        return storedData[dataHash];
    }

    function getStoredDataHash(bytes32 dataHash) public view returns (string memory) {
    return storedData[dataHash];
    }

}
