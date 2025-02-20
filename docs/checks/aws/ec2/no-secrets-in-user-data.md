---
title: no-secrets-in-user-data
---

### Explanation


EC2 instance data is used to pass start up information into the EC2 instance. This userdata must not contain access key credentials. Instead use an IAM Instance Profile assigned to the instance to grant access to other AWS Services.


### Possible Impact
User data is visible through the AWS Management console

### Suggested Resolution
Remove sensitive data from the EC2 instance user-data


### Insecure Example

The following example will fail the aws-ec2-no-secrets-in-user-data check.

```terraform

resource "aws_instance" "bad_example" {

  ami           = "ami-12345667"
  instance_type = "t2.small"

  user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-west-2 
EOF
}

```



### Secure Example

The following example will pass the aws-ec2-no-secrets-in-user-data check.

```terraform

resource "aws_iam_instance_profile" "good_example" {
    // ...
}

resource "aws_instance" "good_example" {
  ami           = "ami-12345667"
  instance_type = "t2.small"

  iam_instance_profile = aws_iam_instance_profile.good_profile.arn

  user_data = <<EOF
  export GREETING=hello
EOF
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-add-user-data.html){:target="_blank" rel="nofollow noreferrer noopener"}


