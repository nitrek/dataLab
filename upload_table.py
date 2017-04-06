# coding: UTF-8


"""
COPYRIGHT (C) 2017 HSBC GBDS GLTc. ALL RIGHTS RESERVED.

No part of this publication may be reproduced, stored in a retrieval system,
or transmitted, on any form or by any means, electronic, mechanical, photocopying,
recording, or otherwise, without the prior written permission of GBDS.

Created By: Terence Feng
Created On: 2017-03-01

Amendment History:

Amended By       Amended On      Amendment Description
------------     -----------     ---------------------------------------------

"""



import sys
from java.lang import Throwable
from subprocess import Popen, PIPE


from gbdspy.aws import pii_hive as gap
from gbdspy.commons import template as gct
from gbdspy.commons import logging as gcl
from gbdspy.commons.util import gen_salt, lower, Stopwatch  ## so that lower() / empty() is visible
from gbdspy.commons import process as gcp

from com.hsbc.gbds.bigdata.common.util.aws import CryptoUtils

import io
import os
import os.path

__metaclass__ = type  # use new style class !

logger = gcl.get_logger(__name__)


UPLOAD_ACTION_COPYFROMHDFS = "copyfromhdfs"
UPLOAD_ACTION_S3SYNC = "s3sync"
UPLOAD_ACTION_CLEAN = "clean"
UPLOAD_ACTIONS = [UPLOAD_ACTION_COPYFROMHDFS, UPLOAD_ACTION_S3SYNC, UPLOAD_ACTION_CLEAN]

BUCKET_ABBREVIATIONS = ["sams", "gducn", "ukdwh", "tdcele"]

def map_abbr_bucket_name(database_name):
    from gbdspy.commons.util import lower
    rs = lower(database_name) # it should be lower case by default, just make sure.
    for k in BUCKET_ABBREVIATIONS:
        if k in rs:
            rs = k
            break
    return rs


def mkdir_p_dir(fname):
    import errno
    import os
    path = os.path.dirname(fname)
    logger.info("File [{}]'s parent directory is [{}].", fname, path)
    try:
        os.makedirs(path)
        logger.info("Directory [{}] was created successfully.", path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            logger.error("Failed to create path [{}]", path)
            raise


class StatusProcess(object):
    def __init__(self, log_cmd=False):
        self.stdout, self.stderr, self.returnCode = None, None, None
        self.log_cmd = log_cmd
        if self.log_cmd:
            logger.info("Property [log_cmd] is True.")

    # def call(self, stdout=PIPE, stderr=STDOUT, *args, **kwargs):
    def call(self, *args, **kwargs):
        """
        args is passed in as tuple.
        :param args:
        :return:
        """
        # self.process = Popen(["klist"], stdout=PIPE, stderr=STDOUT)
        # upd_kwargs = dict(**kwargs)
        # upd_kwargs["stdout"] = PIPE
        # upd_kwargs["stderr"] = STDOUT
        import time
        kwargs.setdefault('stdin', PIPE)
        kwargs.setdefault('stdout', PIPE)
        kwargs.setdefault('stderr', PIPE)
        kwargs.setdefault('close_fds', True)
        if self.log_cmd:
            logger.debug("kwargs is {}", str(kwargs))
        # cleanup variables first:
        self.stdout, self.stderr, self.returnCode = None, None, None
        try:
            _process = Popen(*args, **kwargs)
            # _process = Popen(*args, upd_kwargs)
            MAX_SLEEP_INTERVAL = 30
            # sleep_interval = 1
            # logger.info("... start to keep track progress ...")
            # for line in io.TextIOWrapper(_process.stdout, encoding="utf-8"):  # or another encoding
            #     logger.info("sleep [{}] seconds, current output: {}", str(sleep_interval), line.rstrip())
            # do something with line
            # for line in iter(_process.stdout.readline,''):
            #     if sleep_interval < MAX_SLEEP_INTERVAL:
            #         sleep_interval += 1
            #     # time.sleep(sleep_interval) # delays for 5 seconds
            #     logger.info("sleep [{}] seconds, current output: {}", str(sleep_interval), line.rstrip())
            (self.stdout, self.stderr) = _process.communicate()
            self.returnCode = _process.wait()
        except (Throwable, Exception) as ex:
            if self.stderr is None:
                self.stderr = ex
            logger.error("Error occur: {}", ex)
            type, value, traceback = sys.exc_info()
            logger.error("Unexpected error: type [{}], value [{}], traceback - {}",
                         type, value, traceback)
            # print(traceback.format_exc())

        # logger.info("return code is {} for {}", self.returnCode, args)
        _args = args[0]
        if self.log_cmd:
            _args = args

        if self.returnCode == 0:
            logger.debug("""Command "{}" was executed successfully.""", _args)
        else:
            logger.error("Error occurred - return code is {} for {}, error msg is:\n{}",
                         self.returnCode, _args, self.stderr)
        return None, self.stderr, self.returnCode


class S3Helper(object):
    def __init__(self, app_ctx):
        self.shell_env_map = app_ctx.shell_env_map
        self.p = gcp.Process()

    def list(self, bucket_location):
        cmd = "aws s3 ls --human-readable --recursive {bucket_location}".format(bucket_location=bucket_location)
        logger.info("Start to list bucket content, by running command: [{}] ", cmd)
        sout, serr, rc = self.p.call(cmd, shell=True, env=self.shell_env_map)
        self.print_command_result(cmd, sout, serr, rc)
        return rc

    def sync(self, local_dir, bucket_location):
        _p = StatusProcess()
        # cmd = "aws s3 sync --sse AES256 {local_dir} {bucket_location}".format(
        cmd = "aws s3 sync --sse aws:kms {local_dir} {bucket_location}".format(
            local_dir=local_dir, bucket_location=bucket_location)
        logger.info("Start to sync bucket content, by running command: [{}] ", cmd)
        sout, serr, rc = _p.call(cmd, shell=True, stdout=PIPE, env=self.shell_env_map)
        self.print_command_result(cmd, sout, serr, rc)
        return rc

    def remove(self, bucket_location):
        cmd = "aws s3 rm --recursive {bucket_location}".format(bucket_location=bucket_location)
        logger.info("Start to remove bucket content, by running command: [{}] ", cmd)
        sout, serr, rc = self.p.call(cmd, shell=True, env=self.shell_env_map)
        self.print_command_result(cmd, sout, serr, rc)
        return rc

    def print_command_result(self, cmd, sout, serr, rc):
        if rc == 0:
            logger.info("AWS cli command [{}] was done successfully.", cmd)
        else:
            logger.error("AWS cli command [{}] failed, exit code is [{}], error is: [{}]",
                        cmd, rc, serr)




class AWSCli(object):
    __S3_PREFIX = "s3://"
    __SUPPORTED_AWS_CLI = ["ls"]

    def __init__(self, app_ctx):
        self.app_ctx = app_ctx
        self.s3_helper = S3Helper(app_ctx)
        self.bucket=app_ctx.aws_s3_bucket

    def run(self, param):
        """
        =>  ./halo_aws.sh aws ls [option]
        action should be "ls"

        :param param:
        :return:
        """

        if param is None or len(param) <= 0:
            return self.ls(None)

        action = param[0]
        option = param[1:]
        logger.info(" AWS CLI - action [{}], option [{}].", str(action), str(option))
        if action not in self.__SUPPORTED_AWS_CLI:
            logger.error("Supported aws action are: [{}], but the arguments are: ",
                         " / ".join(self.__SUPPORTED_AWS_CLI))
            for idx, arg in enumerate(param):
                logger.error("  param[{}] is [{}] ", idx, arg)

        if action == "ls":
            return self.ls(option)
        else:
            raise Exception("Unknow action " + action)

    def ls(self, option):
        # self.aws_s3_path = "s3://{bucket}/{bucket_dir_name}".format(
        #     bucket=app_ctx.aws_s3_bucket, bucket_dir_name=self.bucket_dir_name)
        if option is None or len(option) <= 0:
            s3uri = "s3://{bucket}/".format(bucket=self.bucket)
        else:
            uri = option[0]
            if uri.startswith(self.__S3_PREFIX):
                s3uri = uri
            else:
                s3uri = "s3://{bucket}/{uri}".format(bucket=self.bucket, uri=uri)
        # list object:
        return self.s3_helper.list(s3uri)


class AWSUploadProcessor(object):
    def __init__(self, piiHiveDatabase, app_ctx):
        # super(AWSUploadProcessor, self).__init__(database_name)
        if app_ctx is None:
            raise Exception("Unexpected null app_cts.")
        if piiHiveDatabase is None:
            raise Exception("Unexpected null piiHiveDatabase.")
        self.app_ctx = app_ctx
        self.s3_helper = S3Helper(app_ctx)
        self.piiHiveDatabase = piiHiveDatabase
        self.p = gcp.Process()
        # prepare local_staging_dir & aws_s3_path :
        self.database_name = self.piiHiveDatabase.database_name
        self.bucket_dir_name = map_abbr_bucket_name(self.database_name)
        self.local_staging_dir = "staging_data/{database_name}".format(database_name=self.database_name)
        self.aws_s3_path = "s3://{bucket}/{bucket_dir_name}".format(
            bucket=app_ctx.aws_s3_bucket, bucket_dir_name=self.bucket_dir_name)
        logger.info("AWSUploadProcessor - local staging dir is [{}].", self.local_staging_dir)
        logger.info("AWSUploadProcessor - aws s3 path is [{}].", self.aws_s3_path)

    def downloadFromHDFS(self):
        self.cleanup() # pre-clean first.
        target_database_name = self.piiHiveDatabase.target_database_name
        target_database = gap.PIIHiveDatabase(target_database_name, self.app_ctx)
        target_database_location = target_database.location
        # create staging dir:
        mkdir_p_dir(self.local_staging_dir)
        # download from HDFS:
        download_cmd = "hdfs dfs -get {hdfs_location} {local_staging_dir}".format(
            hdfs_location=target_database_location, local_staging_dir=self.local_staging_dir)
        sout, serr, rc = self.p.call(download_cmd, shell=True)
        if rc == 0:
            logger.info("HDFS download for hive database [{}] was done successfully, command is [{}]",
                        self.database_name, download_cmd)
        else:
            logger.info("HDFS download for hive database [{}] failed, exit code is [{}], command is [{}], error is [{}]",
                        self.database_name, download_cmd, serr)
        return rc

    def uploadToAWS_original(self):
        logger.info("start to s3sync hive database [{}]", self.database_name)
        # self.s3_helper.list(self.aws_s3_path)
        self.s3_helper.sync(self.local_staging_dir, self.aws_s3_path)
        self.s3_helper.list(self.aws_s3_path)
        logger.info("End uploading hive database [{}]", self.database_name)

    def uploadToAWS(self):
        from java.io import File
        import os
        logger.info("start to s3sync hive database [{}]", self.database_name)
        # self.s3_helper.list(self.aws_s3_path)
        # self.s3_helper.sync(self.local_staging_dir, self.aws_s3_path)
        staging_dir = File(self.local_staging_dir)
        table_dirs = [dir for dir in staging_dir.list() if staging_dir.isDirectory() ]
        table_count = len(table_dirs)
        logger.info("There were [{}] sub directories under [{}]: ",
                    table_count, self.local_staging_dir, ", ".join(table_dirs))
        for idx, table_dir in enumerate(table_dirs):
            _stopwatch = Stopwatch()
            sub_staging_dir = "{local_staging_dir}/{table_dir}".format(
                local_staging_dir=self.local_staging_dir, table_dir=table_dir)
            sub_aws_s3_path = "{aws_s3_path}/{table_dir}".format(
                aws_s3_path=self.aws_s3_path, table_dir=table_dir)
            indicator = "===> [{cur}/{total}] ".format(cur=(idx+1), total=table_count)
            logger.info("{} - Start to s3sync table [{}] for hive database [{}]",
                        indicator, table_dir, self.database_name)
            rc = self.s3_helper.sync(sub_staging_dir, sub_aws_s3_path)
            _stopwatch.stop()
            if rc == 0 :
                logger.info("{} - End s3sync table [{}] for hive database [{}] successfully, elapse time - {}",
                            indicator, table_dir, self.database_name, str(_stopwatch))
            else:
                logger.error("{} - End s3sync table [{}] for hive database [{}], but error occurred, elapse time - {}",
                             indicator, table_dir, self.database_name, str(_stopwatch))
        self.s3_helper.list(self.aws_s3_path)
        logger.info("End uploading hive database [{}]", self.database_name)

    def cleanup(self):
        if "staging_data" in self.local_staging_dir: # double check by "staging_data" for "rm -rf" !!
            cmd = "rm -rf {staging_dir}".format(staging_dir=self.local_staging_dir)
            sout, serr, rc = self.p.call(cmd, shell=True)
            logger.info("cleanup - run command [{}], exit code is [{}].", cmd, rc)


def write_key(fname, key):
    mkdir_p_dir(fname) # make sure parent path exist.
    with open(fname, 'w') as f:
        f.write(key)
    logger.info("Writing key file [{}] is completed.", fname)


def read_key(fname):
    if not os.path.isfile(fname):
        logger.error("Key file [{}] does not exist.", fname)
        raise Exception("Key file [" + fname + "] does not exist.")

    with open(fname) as f:
        content = f.readlines()
    if content is None or len(content) != 1: # one line only
        logger.error("malformed crypto file [{}], file should exist and contains one line only.", fname)
        raise Exception("malformed crypto file " + fname + ", file should exist and contains one line only.")
    return content[0].strip()


def write_aws_crypto(fname, encrypt_key_id, encrypt_access_key):
    mkdir_p_dir(fname) # make sure parent path exist.
    with open(fname, 'w') as f:
        f.write(encrypt_key_id)
        f.write("\n")
        f.write(encrypt_access_key)
    logger.info("Writing crypto file [{}] is completed.", fname)


def read_aws_crypto(fname):
    if not os.path.isfile(fname):
        logger.error("Crypto file [{}] does not exist.", fname)
        raise Exception("Crypto file [" + fname + "] does not exist.")

    with open(fname) as f:
        content = f.readlines()
    # logger.info("Crypto file [{}], content = [{}], length is [{}]", fname, content, len(content))
    if content is None or len(content) != 2: # 2 lines, encrypt_key_id & encrypt_access_key
        logger.error("malformed crypto file [{}], file should exist and contains 2 lines only.", fname)
        raise Exception("malformed crypto file " + fname + ", file should exist and contains 2 lines only.")
    return content[0].strip(), content[1]


def __main_cipher(app_ctx):
    from java.lang import System
    from java.lang import String
    crypto_utils = CryptoUtils.createAESCrypto()
    encryption_key = crypto_utils.generateKey()
    console = System.console()
    logger.info("{}", "#" * 80)
    logger.info("  Start to input AWS access key id & AWS secret acces key ... ")
    logger.info("  P.S. No echo would display back to the console)")
    logger.info("{}", "#" * 80)
    ## version 1:
    aws_access_key_id = console.readPassword("Please enter AWS access key: ")
    aws_secret_access_key = console.readPassword("Please enter AWS secret access key: ")
    encrypt_key_id = CryptoUtils.toHexString(crypto_utils.encrypt(String(aws_access_key_id), encryption_key))
    encrypt_access_key = CryptoUtils.toHexString(crypto_utils.encrypt(String(aws_secret_access_key), encryption_key))
    ## version 2:
    # aws_access_key_id = console.readLine("Please enter AWS access key: ")
    # aws_secret_access_key = console.readLine("Please enter AWS secret access key: ")
    # encrypt_key_id = CryptoUtils.toHexString(crypto_utils.encrypt(aws_access_key_id, encryption_key))
    # encrypt_access_key = CryptoUtils.toHexString(crypto_utils.encrypt(aws_secret_access_key, encryption_key))
    write_key(app_ctx.aws_crypto_key_path, encryption_key)
    write_aws_crypto(app_ctx.aws_crypto_path, encrypt_key_id, encrypt_access_key)



def pre_upload_init(app_ctx):
    encryption_key = read_key(app_ctx.aws_crypto_key_path)
    encrypt_key_id, encrypt_access_key = read_aws_crypto(app_ctx.aws_crypto_path)
    # start to decrypt:
    crypto_utils = CryptoUtils.createAESCrypto()
    aws_access_key_id = crypto_utils.decrypt(CryptoUtils.convertHexString(encrypt_key_id), encryption_key)
    aws_secret_access_key = crypto_utils.decrypt(CryptoUtils.convertHexString(encrypt_access_key), encryption_key)
    logger.info("Loading aws access key id & aws secret access key was done.")
    app_ctx.update_aws_cipher(aws_access_key_id, aws_secret_access_key)
    # list_aws_bucket(app_ctx)


def populate_aws_upload_processor_map(app_ctx, lower_argv):
    upload_processor_list = [ AWSUploadProcessor(app_ctx.pii_database_map[k], app_ctx) for k in app_ctx.pii_database_map ]
    upload_processor_map = {}
    for processor in upload_processor_list:
        key = map_abbr_bucket_name(processor.database_name)
        upload_processor_map[key] = processor
        logger.info(" ==> avariable source [{}]", key)
    result_map = {}
    for source in BUCKET_ABBREVIATIONS:
        if source in lower_argv:
            result_map[source] = upload_processor_map[source]
    # if no source listed in command line, then append all.
    if len(result_map) == 0:
        result_map.update(upload_processor_map)
    # logger.info("active source is [{}], :: keys for upload_processor_map is [{}]",
    #             str(result_map.keys()), str(upload_processor_map.keys()))
    return result_map


def populate_upload_actions(lower_argv):
    lower_argv_set = set(lower_argv)
    all_actions_set = set(UPLOAD_ACTIONS)
    available_action_set = all_actions_set.intersection(lower_argv_set)
    result_set = set()
    if len(available_action_set) > 0 :
        result_set = available_action_set
    else:
        result_set = all_actions_set
    return result_set
    # source_set = set(BUCKET_ABBREVIATIONS)
    # available_source_set = source_set.intersection(lower_argv_set)


def __main_upload(app_ctx, param_argv):
    logger.info("In __main_upload: ")
    pre_upload_init(app_ctx)

    lower_argv = []
    if param_argv is None or len(param_argv) <= 0:
        logger.info("No parameter for upload")
    else:
        for idx, arg in enumerate(param_argv):
            lower_argv.append(lower(arg))
            logger.info("  upload - param[{}] is [{}] ", idx, arg)

    processor_map = populate_aws_upload_processor_map(app_ctx, lower_argv)
    action_set = populate_upload_actions(lower_argv)
    logger.info("processors keys: [{}], actions: [{}].", str(processor_map.keys()), str(action_set))
    # start processing:
    for source_key in processor_map:
        processor = processor_map[source_key]
        logger.info(" ==> Begin to process source system - [{}].", source_key)
        if UPLOAD_ACTION_COPYFROMHDFS in action_set:
            logger.info("start to copy data from HDFS for source system [{}]", source_key)
            processor.downloadFromHDFS()
        if UPLOAD_ACTION_S3SYNC in action_set:
            logger.info("start to s3sync source system [{}]", source_key)
            processor.uploadToAWS()
        if UPLOAD_ACTION_CLEAN in action_set:
            logger.info("start to clean local source system [{}] data folder.", source_key)
            processor.cleanup()
    # for processor in upload_processor_list:
    #     processor.downloadFromHDFS()
    #     processor.uploadToAWS()
    #     processor.cleanup()
    logger.info("AWS update is completed ! ")


def __main_awscli(app_ctx, param_argv):
    awscli = AWSCli(app_ctx)
    return awscli.run(param_argv)


def main_awscli(app_ctx, param_argv):
    error_rc = 0
    try:
        __main_awscli(app_ctx, param_argv)
        error_rc = 0
    except:
        error_rc = -1  # abnormal exit
        raise
    return error_rc

def main_cipher(app_ctx):
    error_rc = 0
    try:
        __main_cipher(app_ctx)
        error_rc = 0
    except:
        error_rc = -1  # abnormal exit
        raise
    return error_rc


def main_upload(app_ctx, param_argv):
    error_rc = 0
    failed_table_count = 0
    try:
        __main_upload(app_ctx, param_argv)
        error_rc = 0
    except:
        error_rc = -1  # abnormal exit
        raise
    return error_rc


print ("module %s Loaded..." % __name__)



