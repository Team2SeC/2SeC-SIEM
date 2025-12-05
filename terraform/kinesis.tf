#--------------------------------------------------------------
# 2SeC SIEM Infrastructure - Kinesis Data Stream
#--------------------------------------------------------------

#--------------------------------------------------------------
# Kinesis Data Stream
#--------------------------------------------------------------
resource "aws_kinesis_stream" "main" {
  name             = "${var.project_name}-log-stream"
  shard_count      = var.kinesis_shard_count
  retention_period = var.kinesis_retention_hours

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  encryption_type = "KMS"
  kms_key_id      = "alias/aws/kinesis"

  tags = {
    Name = "${var.project_name}-log-stream"
  }
}

#--------------------------------------------------------------
# Kinesis CloudWatch Metrics
#--------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "kinesis_get_records" {
  alarm_name          = "${var.project_name}-kinesis-iterator-age"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GetRecords.IteratorAgeMilliseconds"
  namespace           = "AWS/Kinesis"
  period              = 300
  statistic           = "Maximum"
  threshold           = 60000 # 1분
  alarm_description   = "Kinesis iterator age is too high - consumer falling behind"

  dimensions = {
    StreamName = aws_kinesis_stream.main.name
  }

  tags = {
    Name = "${var.project_name}-kinesis-alarm"
  }
}
