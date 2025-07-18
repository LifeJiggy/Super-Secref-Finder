import re

SENSITIVE_PATTERNS = {
    # API Keys and Tokens
    "api_key": r"\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|bearer)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,64})['\"]?",
    "aws_access_key_id": r"\bAKIA[0-9A-Z]{16}\b(?!\S)",
    "aws_secret_access_key": r"\b[A-Za-z0-9/\+]{40}\b(?!\S)",
    "aws_session_token": r"\bFQoGZXIvYXdzE[a-zA-Z0-9/\+]+\b",
    "google_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b(?!\S)",
    "paypal_client_id": r"\bA[a-zA-Z0-9_-]{38,60}\b(?!\S)",
    "mobile_appcenter_secret": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    "github_token": r"\bgh[puor]_[A-Za-z0-9]{36,76}\b",
    "sendgrid_api_key": r"\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43}\b",
    "stripe_key": r"\b(?:pk|sk|rk)_[live|test]_[0-9a-zA-Z]{24,}\b",
    "twilio_api_key": r"\bSK[0-9a-fA-F]{32}\b",
    "heroku_api_key": r"\b[hH]eroku[_-]?[0-9a-fA-F]{32}\b",
    "mailgun_api_key": r"\bkey-[0-9a-zA-Z]{32}\b",
    "facebook_access_token": r"\bEAACEdEose0cBA[0-9A-Za-z]+\b",
    "digitalocean_personal_access_token": r"\bdop_v1_[a-f0-9]{64}\b",
    "asana_personal_access_token": r"\b0/[0-9a-z]{32}\b",

    # Credentials and Secrets
    "hardcoded_credential": r"\b(?:user(?:name)?|pass(?:word)?|cred(?:ential)?|secret)\s*[:=]\s*['\"]?([^\s\"']{6,})['\"]?",
    "jwt_token": r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]{20,}\b",  # Tightened for valid JWT
    "session_id": r"\b(?:session_id|sid|sess|phpsessid)\s*[:=]\s*['\"]?([\w-]{16,64})['\"]?",
    "client_id": r"\b(?:client[_-]?id|oauth[_-]?client)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,64})['\"]?",
    "client_secret": r"\bclient[_-]?secret\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,64})['\"]?",
    "django_secret_key": r"\bSECRET_KEY\s*=\s*['\"](.{50,})['\"]",

    # URLs and Endpoints
    "api_endpoint": r"\bhttps?:\/\/[^\"\'\s]+\/(?:api\/v\d+[^\"\'\s]*|graphql[^\"\'\s]*)\b",
    "admin_endpoint": r"/admin(?:/|$)",
    "debug_endpoint": r"/debug(?:/|$)",
    "test_endpoint": r"/test(?:/|$)",
    "oauth_endpoint": r"/oauth/(?:authorize|token)(?:/|$)",
    "openid_connect_endpoint": r"/\.well-known/openid-configuration(?:/|$)",

    # Cloud Resources
    "s3_bucket_url": r"\bhttps?:\/\/([a-zA-Z0-9\-_\.]+)\.s3(?:-[a-zA-Z0-9\-]+)?\.amazonaws\.com\b",
    "aws_arn": r"\barn:aws:[a-zA-Z0-9\-]+:[a-z\-0-9]*:\d{12}:[^\"\'\s]+\b",
    "aws_rds_endpoint": r"\b[a-z0-9\-]+\.rds\.amazonaws\.com\b",
    "aws_dynamodb_url": r"\bdynamodb\.[a-z0-9\-]+\.amazonaws\.com\b",
    "aws_cloudfront_url": r"\bcloudfront\.net/[a-zA-Z0-9]+\b",

    # Database URIs
    "mongodb_uri": r"\bmongodb(?:\+srv)?:\/\/[^\"\'\s]+\b",
    "mysql_uri": r"\bmysql:\/\/[^\"\'\s]+\b",
    "postgres_uri": r"\bpostgres(?:ql)?:\/\/[^\"\'\s]+\b",
    "redis_uri": r"\bredis:\/\/[^\"\'\s]+\b",
    "mssql_db_uri": r"\bmssql:\/\/[^\"\'\s]+\b",
    "oracle_db_uri": r"\boracle:\/\/[^\"\'\s]+\b",

    # Dangerous JavaScript Functions
    "dangerous_function": r"\b(?:eval|execScript|document\.write|document\.writeln)\s*\(",
    "dangerous_innerhtml": r"\.innerHTML\s*=\s*[^;]+",
    "dangerous_outerhtml": r"\.outerHTML\s*=\s*[^;]+",
    "dangerous_blob_url": r"\bURL\.createObjectURL\s*\(",
    "dangerous_window_open": r"\bwindow\.open\s*\(",
    "dangerous_location": r"\blocation\.(assign|replace)\s*\(",

    # Inline Scripts and HTML
    "inline_script": r"<script[^>]*>(.*?)</script>",
    "dangerous_iframe": r"<iframe[^>]+src=['\"][^\"']+['\"]",

    # File Operations
    "file_operation": r"\b(?:readFile|writeFile|copyFile|moveFile|deleteFile|unlink|fs\.(read|write|copy|rename|unlink)|file_(get|put)_contents)\s*\(",
    "file_execute": r"\b(?:exec|spawn|system|popen|shell_exec|passthru|proc_open)\s*\(",
    "file_inclusion": r"\b(?:require|include|import)\s*\(\s*['\"][^\"']+['\"]\s*\)",

    # Security Headers and Policies
    "cors_wildcard": r"\bAccess-Control-Allow-Origin:\s*\*",
    "cookie_flag": r"\bSet-Cookie:\s*([^;]+);",
    "http_authorization_header": r"\bAuthorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*",

    # Sensitive Comments
    "sensitive_comment": r"<!--\s*(secret|password|todo|fixme|debug|remove)[^>]*-->",
    "fixme_comment": r"//\s*FIXME[:]?",
    "todo_comment": r"//\s*TODO[:]?",

    # Potential Vulnerabilities
    "path_traversal": r"\.\.\/+",
    "lfi_vector": r"\.\.\/\.\.\/",
    "ssrf_vector": r"\b(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\b",
    "xss_payload": r"<img\s+src=['\"][^\"']*onerror=['\"][^\"']*['\"]",

    # Storage Operations
    "local_storage": r"\blocalStorage\.setItem\s*\(\s*['\"]?([^\"']+)['\"]?\s*,\s*['\"]?([^\"']+)['\"]?\s*\)",
    "session_storage": r"\bsessionStorage\.setItem\s*\(\s*['\"]?([^\"']+)['\"]?\s*,\s*['\"]?([^\"']+)['\"]?\s*\)",

    # Logging and Debugging
    "log_statement": r"\bconsole\.(log|debug|warn|error|trace)\s*\(",
    "error_message": r"\b(?:Exception|Error|Traceback|Stacktrace)\s*:?\s*[^\s\"']+\s*(?:at\s+[^\s\"']+|\([^)]+\))",

    # User and Authentication Operations
    "user_auth": r"\b(?:login|logout|register|resetPass(?:word)?|verifyEmail|isAuthenticated|requireAuth)\s*\(",
    "user_management": r"\b(?:activate|deactivate|ban|unban|block|unblock|suspend|unsuspend|delete)(?:User|Account|Member)\s*\(",
    "user_permission": r"\b(?:has|assign|check)(?:Role|Permission)\s*\(",
    "user_payment": r"\bprocess(?:Payment|Refund|Charge)\s*\(",
    "user_subscription": r"\b(?:subscribe|unsubscribe|renewSubscription)\s*\(",
}

def validate_pattern(pattern_name, match_str):
    """
    Additional validation to reduce false positives.
    """
    if pattern_name == "hardcoded_credential":
        return not re.search(r"password\s*:\s*[!0-9]|void|return|function", match_str, re.IGNORECASE)
    elif pattern_name == "error_message":
        return re.search(r"(Exception|Error|Traceback|Stacktrace)\s*:?\s*[^\s\"']+\s*(?:at\s+[^\s\"']+|\([^)]+\))", match_str, re.IGNORECASE)
    elif pattern_name == "file_inclusion":
        return re.search(r"\.(js|php|py|html|css|txt|json|xml)$", match_str, re.IGNORECASE)
    elif pattern_name == "paypal_client_id":
        return len(match_str) in [38, 40, 60] and match_str.startswith("A")
    elif pattern_name == "mobile_appcenter_secret":
        # Exclude known benign UUIDs (e.g., GitHub analytics or CookieLaw)
        benign_uuids = [
            "e8504c0e-76d8-4281-a0c5-06547e2242a4",
            "693d30c4-f1db-de12-46ee-1a30cf025e61",
            "bd4cff8d-7544-4d25-997c-7399dc325ab0",
            "3562dcde-471d-450b-a41d-ed0f4ebc9843",
            "52e658ee-26cb-4051-879f-9ecff283eb62"
        ]
        return match_str not in benign_uuids
    elif pattern_name == "jwt_token":
    
    
    
        # Exclude SVG filenames or short tokens
        return not re.search(r"\.svg$|\.png$|\.jpg$", match_str, re.IGNORECASE) and len(match_str) > 50
    return True