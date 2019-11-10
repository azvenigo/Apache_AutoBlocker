# Apache_AutoBlocker
 A Single, self-contained PHP script to automatically ban IPs that try to scan for vulnerabilities. 

# How does it work
 A common technique malicious actors try is running scripts to scan for vulnerabilities on your web site.
 
 If you look in your access.log you can see anywhere from dozens to hundreds of these requests from a single IP address.
 Example from my logs:
 ```
154.223.160.188 - - [07/Nov/2019:20:24:55 -0800] "GET / HTTP/1.1" 200 38
154.223.160.188 - - [07/Nov/2019:20:24:55 -0800] "GET /robots.txt HTTP/1.1" 404 179
154.223.160.188 - - [07/Nov/2019:20:24:56 -0800] "POST /Adminb325e749/Login.php HTTP/1.1" 404 192
154.223.160.188 - - [07/Nov/2019:20:24:56 -0800] "GET / HTTP/1.1" 200 38
154.223.160.188 - - [07/Nov/2019:20:24:58 -0800] "GET /l.php HTTP/1.1" 404 174
154.223.160.188 - - [07/Nov/2019:20:24:59 -0800] "GET /phpinfo.php HTTP/1.1" 404 180
154.223.160.188 - - [07/Nov/2019:20:24:59 -0800] "GET /test.php HTTP/1.1" 404 177
154.223.160.188 - - [07/Nov/2019:20:24:59 -0800] "POST /index.php HTTP/1.1" 404 178
```

Notice how there are numerous requests for files that do not exist on the server. This simple script will detect when too many of these requests are occuring from a single source and ban them from any additional access to the server. (Legitimate or otherwise.)

# Usage
  * Install/Enable PHP on your Apache server
  * Add this file to your site.
     * Configure the variables in the script for your site.
     * There are four variables in the configuration section along with explanations of what they do.
  * Direct Apache to server this file as a 404 response
     * In "httpd.conf" add this line: ErrorDocument 404 "/example_path/apache_auto_blocker.php"
  * Restart Apache and test by hitting a non-existent file on your site enough times to trigger the ban
     * You can undo the ban by removing the banned IP address from the newly created .htaccess file.
     * Note: No restart is required after adding or removing entries from .htaccess
     
That's it. From then on you can see what sites have been banned by watching your .htaccess file. You can also do an IP lookup from various services online to see from where the malicious IP address originated.

