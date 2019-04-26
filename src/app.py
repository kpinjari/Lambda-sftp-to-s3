from botocore.exceptions import ClientError
import boto3, json, re, os, logging, yaml, sys, time
import pysftp

logger = logging.getLogger()
configuration_file = 'configuration.yaml'

def setupLogging(loglevel, context, GUID):
    for h in logger.handlers:
      logger.removeHandler(h)
    
    FORMAT = '[%(levelname)s]    %(asctime)s.%(msecs)03dZ    '+os.environ["ENV"]+'    '+os.environ["REGION"]+'    '+context.function_name+'    '+GUID+'    %(message)s'
    h = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(FORMAT,"%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime
    formatter.default_msec_format = '%s.%03d'
    h.setFormatter(formatter)
    logger.addHandler(h)

    logger.setLevel(loglevel)
    logger.debug('Logging driver configured...')

def get_configurations(configuration_file):
    """
    Get configuration from configuration.yaml
    """
    with open(configuration_file, 'r') as stream:
        try:
            config = yaml.safe_load(stream)
            s3_bucket = config.get('S3_BUCKET')
            secret_name = config.get('SECRET_MANAGER').get('name')
            sftpPath = config.get('SECRET_MANAGER').get('keys').get('sftpPath')
            sftpUserName = config.get('SECRET_MANAGER').get('keys').get('sftpUserName')
            sftpPassword = config.get('SECRET_MANAGER').get('keys').get('sftpPassword')
            remoteDirectory = config.get('SECRET_MANAGER').get('keys').get('remoteDirectory')
            regex = config.get('REGULAR_EXPRESSION')
            output_file_prefix = config.get('OUTPUT_FILE_PREFIX')
            table_name = config.get('DYNAMODB_TABLE').get('name')
            primary_field_name = config.get('DYNAMODB_TABLE').get('columns').get('primaryCol')
            second_field_name = config.get('DYNAMODB_TABLE').get('columns').get('sortCol')
        except yaml.YAMLError as exc:
            logger.error('Error in parsing configuration YAML : {}'.format(exc))
            raise exc
    return s3_bucket,secret_name,sftpPath,sftpUserName,sftpPassword,remoteDirectory,regex,output_file_prefix,table_name,primary_field_name,second_field_name

def lambda_handler(event, context):
    """
    This lambda function fetch the sfmc rejection file (specific naming convention as per regex) from sftc location and put it into S3
    """
    sftp = None
    region_name = os.environ["REGION"]
    try:
        if isinstance(event, str):
            event = json.loads(event)
        GUID = context.aws_request_id
        setupLogging(logging.DEBUG, context, GUID)
        logger.info('EVENT {} {}'.format(type(event), event))
        logger.debug('CONTEXT {}'.format(context))

        s3_bucket,secret_name,sftpPathKey,sftpUserNameKey,sftpPasswordKey,remoteDirectoryKey,regex,output_file_prefix,table_name,primary_field_name,second_field_name = get_configurations(configuration_file)
        ftppath,ftpusername,ftppassword,remoteDirectory = get_aws_secrects(secret_name,region_name,sftpPathKey,sftpUserNameKey,sftpPasswordKey,remoteDirectoryKey)
        cnopts = pysftp.CnOpts()
        cnopts.hostkeys = None
        sftp = pysftp.Connection(ftppath, username=ftpusername, password=ftppassword, cnopts=cnopts)
        sftp.cwd(remoteDirectory)
        data = sftp.listdir()
        for filename in data:
            if re.fullmatch(regex, filename):
                if not is_item_exists(table_name,primary_field_name,filename,region_name):
                    mapped_file_name = output_file_prefix + filename.split(" ")[-1]
                    sftpfileobject = sftp.open(filename, mode='r', bufsize=-1)
                    res1 = put_file_in_s3(s3_bucket,sftpfileobject.read(size=-1),filename,mapped_file_name,region_name)
                    if res1['ResponseMetadata']['HTTPStatusCode'] == 200:
                        logger.info('File {} synced to S3 bucket {}'.format(filename, s3_bucket))
                    else:
                        logger.info(str(res1['ResponseBody']))
                    res2 = insert_item(filename, mapped_file_name,region_name,table_name,primary_field_name,second_field_name)
                    if res2['ResponseMetadata']['HTTPStatusCode'] == 200:
                        logger.info('Database updated with file sync information')
                    else:
                        logger.info(str(res2['ResponseBody']))
                else:
                    logger.info('File {} already synced in past'.format(filename))
    except Exception as exc:
        logger.error(str(exc))
    finally:
        if sftp is not None:
            sftp.close()

def put_file_in_s3(s3_bucket,sftpfileobjectbytes,filename,mapped_file_name,region_name):
    s3client = boto3.resource('s3', region_name=region_name)
    response = None
    try:
        response = s3client.Object(s3_bucket,mapped_file_name).put(Body=sftpfileobjectbytes)
    except ClientError as err:
        logger.error('Error in uploading the file {} in S3 bucket {}'.format(filename, s3_bucket))
        raise err
    return response

def is_item_exists(table_name,primary_field_name,filename,region_name):
    """
    Check in DynamoDB if file has been already sync in past
    """
    dynamodb = boto3.resource('dynamodb',region_name=region_name)
    table = dynamodb.Table(table_name)
    item_exists = False
    try:
        response = table.get_item(Key={primary_field_name: filename})
        if 'Item' in response:
            item_exists = True
    except Exception as e:
        raise e
    return item_exists

def insert_item(filename,mappedfilename,region_name,table_name,primary_field_name,second_field_name):
    """
    Insert filename in DynamoDB
    """
    dynamodb = boto3.resource('dynamodb',region_name=region_name)
    table = dynamodb.Table(table_name)
    response = None
    try:
        response = table.put_item(Item={primary_field_name: filename,second_field_name: mappedfilename})
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        raise e
    return response

def get_aws_secrects(secret_name,region_name,sftpPathKey,sftpUserNameKey,sftpPasswordKey,remoteDirectoryKey):
    """
    Get secrets from AWS SecretManager
    """
    ftpPath = None
    ftpUserName = None
    ftpPassword = None
    remoteDirectory = None

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            logger.error('Secrets Manager can not decrypt the protected secret text using the provided KMS key.')
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            logger.error('An error occurred on the server side.')
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.error('You provided an invalid value for a parameter.')
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.error('You provided a parameter value that is not valid for the current state of the resource.')
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.error('We can not find the resource that you asked for.')
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            jsonStr = json.loads(secret)
            ftpPath = jsonStr[sftpPathKey]
            ftpUserName = jsonStr[sftpUserNameKey]
            ftpPassword = jsonStr[sftpPasswordKey]
            remoteDirectory = jsonStr[remoteDirectoryKey]
    return ftpPath, ftpUserName, ftpPassword, remoteDirectory