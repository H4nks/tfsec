---
title: alb-not-public
---

### Explanation


There are many scenarios in which you would want to expose a load balancer to the wider internet, but this check exists as a warning to prevent accidental exposure of internal assets. You should ensure that this resource should be exposed publicly.


### Possible Impact
The load balancer is exposed on the internet

### Suggested Resolution
Switch to an internal load balancer or add a tfsec ignore


### Insecure Example

The following example will fail the aws-elbv2-alb-not-public check.

```terraform

resource "aws_alb" "bad_example" {
	internal = false
}

```



### Secure Example

The following example will pass the aws-elbv2-alb-not-public check.

```terraform

resource "aws_alb" "good_example" {
	internal = true
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb){:target="_blank" rel="nofollow noreferrer noopener"}


