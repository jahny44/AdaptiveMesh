# Adaptive Security Mesh for MCP

A dynamic security framework that automatically adjusts security measures based on real-time conditions and threat intelligence.

## Core Features

### 1. Adaptive Security Levels
- Four-tier security classification (LOW, MEDIUM, HIGH, CRITICAL)
- Dynamic adjustment based on:
  - Message sensitivity
  - Real-time threat intelligence
  - Network conditions
  - User context

### 2. Access Control
- Role-based access control (RBAC)
- Four access levels:
  - PUBLIC
  - INTERNAL
  - CONFIDENTIAL
  - RESTRICTED
- Tool-specific access policies
- Credential-based authentication

### 3. Data Protection
- Automatic data classification
- Pattern-based sensitive data masking
- Multi-level encryption
- Access control metadata

### 4. Threat Intelligence Integration
- Multiple threat intelligence sources
- Real-time threat level assessment
- Dynamic security policy adjustment

### 5. Protocol Management
- Dynamic cryptographic protocol selection
- Support for multiple protocols:
  - TLS 1.3
  - AES-256
  - RSA-4096
- Protocol strength matching to security level

## Technical Implementation

### Core Components

```python
class SecurityMesh:
    """Core security mesh implementation"""
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.classification_engine = ClassificationEngine()
        self.protocol_manager = ProtocolManager()
        self.credential_manager = CredentialManager()
        self.threat_intelligence = ThreatIntelligenceManager()
        self.security_features = SecurityFeatures(policy)
```

### Security Features Implementation

```python
class SecurityFeatures:
    """Implementation of specific security features"""
    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.tool_policies: Dict[str, ToolAccessPolicy] = {}
        self._load_tool_policies()
```

### Configuration Management

```python
@dataclass
class SecurityConfig:
    """Security configuration container"""
    policy_file: Path
    threat_intelligence_sources: List[str]
    credential_stores: List[str]
    protocol_registry: Dict[str, Dict]
```

### Integration Points

```python
class SecurityMiddleware:
    """Middleware for integrating security mesh with MCP server"""
    def __init__(self, config: SecurityConfig):
        self.config = config
        self.policy = load_security_policy(config)
        self.security_mesh = SecurityMesh(self.policy)
```

## Key Technical Features

### 1. Policy-Based Security
- YAML-based configuration
- Dynamic policy loading
- Hierarchical security rules

### 2. Data Processing Pipeline
- Input validation and sanitization
- Output security processing
- Automatic data classification

### 3. Security Measures
- Pattern-based sensitive data masking
- Multi-level encryption
- Access control metadata
- Credential management

### 4. Integration Architecture
- Middleware-based integration
- Factory pattern for server creation
- Asynchronous processing
- Event-based security updates

## Example Usage

```python
# Create secure server
server = create_secure_stdio_server(
    params=server_params,
    config_path=str(config_path),
    name="Secure MCP Server"
)

# Connect with security validation
await server.connect()

# List tools with access control
tools = await server.list_tools()

# Call tool with security validation
result = await server.call_tool(
    "example_tool",
    {"input": "sensitive data"}
)
```

## Configuration

The security mesh is configured through YAML files:

```yaml
# Security Policy Configuration

# Default security level
default_level: MEDIUM

# Sensitivity thresholds for different data types
sensitivity_thresholds:
  personal_data: 0.8
  financial_data: 0.9
  health_data: 0.95
  public_data: 0.2
  business_data: 0.7

# Protocol mappings for each security level
protocol_mappings:
  LOW:
    - tls_1_3
  MEDIUM:
    - tls_1_3
    - aes_256
  HIGH:
    - tls_1_3
    - aes_256
    - rsa_4096
  CRITICAL:
    - tls_1_3
    - aes_256
    - rsa_4096

# Credential requirements for each security level
credential_requirements:
  LOW:
    - basic_auth
  MEDIUM:
    - oauth2
    - api_key
  HIGH:
    - oauth2
    - api_key
    - certificate
  CRITICAL:
    - oauth2
    - api_key
    - certificate
    - mfa
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/jahny44/AdaptiveMesh.git
cd AdaptiveMesh
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure security settings:
- Copy `examples/security/config.yaml` to your project
- Adjust settings according to your needs

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
