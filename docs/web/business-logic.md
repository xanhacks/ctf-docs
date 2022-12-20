# Business logic vulnerability

## Definition

Business logic vulnerabilities are weaknesses in the way a business system or application is designed or implemented that can be exploited by attackers to gain unauthorized access to resources, disrupt business processes, or steal sensitive data.

To protect against business logic vulnerabilities, it is important to follow best practices for secure application design and implementation, including input validation, access control, secure data storage, and strong authentication and authorization controls.

## Examples

- Buy products with negative quantity
- Change email in setting to `@company`
- Apply Coupon1, then Coupon2, then 1, then 2, ...
- Price that goes over 2,147,483,647, and go negative
- Length of email > 255 (bypass end of domain)
    - "AAAA...AAAA@victim.com" (255 len) + ".evil.com"
- Omit current password input
- Bypass verification, add to cart -> verif amount -> add to cart -> confirm order
- Drop request to select low priv roles
- Cryptography oracle to encrypt/decrypt