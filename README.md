## Testing

    pip install -r src/requirements.in
    pip install -r src/tests/unit/requirements.in

To execute all tests run following

    python3 -m unittest discover

Or you can run specific test case or cases as following

    python3 -m unittest src.tests.unit.test_handler
    python3 -m unittest src.tests.unit.test_handler.TestSfmcSftpRejectionLambda
    python3 -m unittest src.tests.unit.test_handler.TestSfmcSftpRejectionLambda.test_dynamodb_insert_get
    python3 -m unittest src.tests.unit.test_handler.TestSfmcSftpRejectionLambda.test_put_file_in_s3
