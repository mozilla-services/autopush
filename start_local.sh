#! /bin/sh

echo "=== Starting local DDB:"
java -Xmx1G -Djava.library.path=ddb -jar ddb/DynamoDBLocal.jar -sharedDb --inMemory &
echo "=== Waiting for DDB"
sleep 5
echo "=== Starting autopush endpoint:"
AWS_LOCAL_DYNAMODB=http://localhost:8000 autoendpoint --log_level debug &
sleep 5
echo "=== Starting autopush:"
AWS_LOCAL_DYNAMODB=http://localhost:8000 autopush --log_level debug
echo "=== closing down..."