// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title AuditRegistry
/// @notice Decentralized registry for smart contract audit reports
/// @dev Part of the Ethereum Security Toolkit public good
contract AuditRegistry {
    struct Report {
        address auditor;
        address target;
        uint8 severity; // 0=info, 1=low, 2=medium, 3=high, 4=critical
        string ipfsCid;
        uint256 timestamp;
        bool verified;
    }

    Report[] public reports;
    mapping(address => uint256[]) public reportsByTarget;
    mapping(address => uint256[]) public reportsByAuditor;
    mapping(address => bool) public trustedAuditors;
    address public governance;

    event ReportSubmitted(uint256 indexed id, address indexed target, address indexed auditor, uint8 severity);
    event AuditorTrusted(address indexed auditor);

    modifier onlyGovernance() { require(msg.sender == governance, "not governance"); _; }

    constructor() { governance = msg.sender; }

    function submitReport(address target, uint8 severity, string calldata ipfsCid) external returns (uint256 id) {
        require(severity <= 4, "invalid severity");
        id = reports.length;
        reports.push(Report(msg.sender, target, severity, ipfsCid, block.timestamp, trustedAuditors[msg.sender]));
        reportsByTarget[target].push(id);
        reportsByAuditor[msg.sender].push(id);
        emit ReportSubmitted(id, target, msg.sender, severity);
    }

    function trustAuditor(address auditor) external onlyGovernance {
        trustedAuditors[auditor] = true;
        emit AuditorTrusted(auditor);
    }

    function getReportCount() external view returns (uint256) { return reports.length; }
    function getTargetReports(address target) external view returns (uint256[] memory) { return reportsByTarget[target]; }
}
