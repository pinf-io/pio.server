#!/bin/bash -e

URL="http://127.0.0.1:$PORT/"

echo "URL: $URL"

STATUS_CODE=$(curl -w %{http_code} -s --output /dev/null $URL)

echo "STATUS_CODE: $STATUS_CODE"

if [ $STATUS_CODE != 200 ]; then
	echo "Did not get 200!";
	echo '<wf name="result">{"success": false}</wf>'
	exit 1;
fi

echo '<wf name="result">{"success": true}</wf>'

exit 0;
