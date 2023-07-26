# JSON Schema

*Schema for defining an environment*

## Properties

- **`AccountId`** *(string)*
- **`Name`** *(string)*
- **`CidrRanges`** *(object)*: Cannot contain additional properties.
  - **`ap-northeast-1`** *(string)*
  - **`ap-southeast-1`** *(string)*
  - **`eu-central-1`** *(string)*
  - **`eu-west-1`** *(string)*
  - **`sa-east-1`** *(string)*
  - **`ca-central-1`** *(string)*
  - **`us-east-1`** *(string)*
  - **`us-east-2`** *(string)*
- **`Rules`** *(array)*
  - **Items**: Refer to *[#/definitions/Rule](#definitions/Rule)*.

  Examples:
  ```yaml
  Description: Allow traffic to reach the outbound destinations
  Destinations:
  -   $ref: '#/definitions/Destination'
  Name: Outbound Connectivity
  Sources:
  -   $ref: '#/definitions/Source'
  Type: Egress
  ```

## Definitions

- <a id="definitions/Rule"></a>**`Rule`** *(object)*: Cannot contain additional properties.
  - **`Name`** *(string, required)*
  - **`Type`**: Must be one of: `["Egress", "Inspection"]`.
  - **`Description`** *(string, required)*
  - **`Sources`** *(array, required)*
    - **Items**: Refer to *[#/definitions/Source](#definitions/Source)*.
  - **`Destinations`** *(array, required)*
    - **Items**: Refer to *[#/definitions/Destination](#definitions/Destination)*.
- <a id="definitions/Source"></a>**`Source`** *(object)*: Cannot contain additional properties.
  - **`Description`** *(string, required)*
  - **`Cidr`** *(string)*
  - **`Region`** *(string)*

  Examples:
  ```yaml
  Cidr: 10.0.0.0/8
  Description: Allow access from `10.0.0.0/8` to the defined destinations.
  ```

  ```yaml
  Description: Allow access from `eu-central-1` to the defined destinations.
  Region: eu-central-1
  ```

- <a id="definitions/Destination"></a>**`Destination`** *(object)*: Cannot contain additional properties.
  - **Any of**
    - 
    - 
    - 
  - **`Description`** *(string, required)*
  - **`Endpoint`** *(string)*
  - **`Cidr`** *(string)*
  - **`Region`** *(string)*
  - **`Protocol`**: Must be one of: `["TCP", "TLS", "ICMP"]`.
  - **`Port`** *(integer)*

  Examples:
  ```yaml
  Description: Website of Xebia
  Endpoint: xebia.com
  Port: 443
  Protocol: TLS
  Region: eu-central-1
  ```

