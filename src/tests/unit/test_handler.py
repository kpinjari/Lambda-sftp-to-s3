import unittest
import boto3, json, time
from src.app import put_file_in_s3, insert_item, is_item_exists
from moto import mock_dynamodb2, mock_s3

class TestSfmcSftpRejectionLambda(unittest.TestCase):

    @mock_dynamodb2
    def test_dynamodb_insert_get(self):
        region_name = 'eu-central-1'
        dynamodb_client = boto3.resource('dynamodb', region_name)
        table_name = 'SFTPFileExtractRecord'
        primary_field_name = 'FileName'
        second_field_name = 'MappedFileName'
        dbtable = dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'FileName',
                    'KeyType': 'HASH'
                },
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'FileName',
                    'AttributeType': 'S'
                },
                {
                    'AttributeName': 'MappedFileName',
                    'AttributeType': 'S'
                },
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        dbtable.meta.client.get_waiter('table_exists').wait(TableName=table_name)
        assert dbtable.item_count == 0
        filename = 'sample_sfmc_rejection_file.csv'
        mappedfilename = 'sfmc_global_rejection_file.csv'
        assert insert_item(filename,mappedfilename,region_name,table_name,primary_field_name,second_field_name)['ResponseMetadata']['HTTPStatusCode'] == 200
        assert is_item_exists(table_name,primary_field_name,filename,region_name) == True


    @mock_s3
    def test_put_file_in_s3(self):
        region_name = 'eu-central-1'
        bucket_name='td-datamigr-sfmc-sftp-rejection-dev'
        s3_conn = boto3.client('s3', region_name=region_name)
        s3_conn.create_bucket(Bucket=bucket_name)
        filename = 'sample_sfmc_rejection_file.csv'
        mappedfilename = 'sfmc_global_rejection_file.csv'
        put_file_in_s3(bucket_name,b'It is a test body', filename, mappedfilename, region_name)
        for item in s3_conn.list_objects(Bucket=bucket_name)['Contents']:
            assert item['Key'] == mappedfilename

if __name__ == '__main__':
    unittest.main()