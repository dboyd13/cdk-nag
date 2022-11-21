/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import { parse } from 'path';
import { CfnResource, Stack } from 'aws-cdk-lib';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { CfnKey } from 'aws-cdk-lib/aws-kms';
import { NagRuleCompliance } from '../../nag-rules';

/**
 * IAM condition key and operator combinations that are believed to be common and easily evaulatiion approaches to mitigate "external access" where '*' is used in Principal
 *
 * NOTE: These checks are not and do not aim to be complete, they aim to reduce false-positives versus only checking for '*' in Principal, by checking for common high-confidence mitigations implemented as Conditions. For more comprehensive coverage, please use IAM Access Analyzer (https://aws.amazon.com/blogs/security/validate-iam-policies-in-cloudformation-templates-using-iam-access-analyzer/)
 *
 */
const commonMitigatingConditions = [
  {
    conditionKey: 'aws:PrincipalOrgId',
    conditionOperator: 'StringEquals',
    WildcardInKeyValueIsNonCompliant: false,
  },
  {
    conditionKey: 'aws:PrincipalOrgId',
    conditionOperator: 'StringEqualsIgnoreCase',
    WildcardInKeyValueIsNonCompliant: false,
  },
  {
    conditionKey: 'aws:PrincipalArn',
    conditionOperator: 'StringEquals',
    WildcardInKeyValueIsNonCompliant: false,
  },
  {
    conditionKey: 'aws:PrincipalArn',
    conditionOperator: 'StringEqualsIgnoreCase',
    WildcardInKeyValueIsNonCompliant: false,
  },
  {
    conditionKey: 'aws:PrincipalArn',
    conditionOperator: 'ArnEquals',
    WildcardInKeyValueIsNonCompliant: true,
  },
  {
    conditionKey: 'aws:PrincipalArn',
    conditionOperator: 'ArnLike',
    WildcardInKeyValueIsNonCompliant: true,
  },
];

/**
 * KMS key policies do not allow for open access
 *
 * NOTE: These checks are not and are do not aim to be complete, they aim to reduce false-positives versus only checking for '*' in Principal, by checking for common high-confidence mitigations implemented as Conditions. For more comprehensive coverage, please use IAM Access Analyzer (https://aws.amazon.com/blogs/security/validate-iam-policies-in-cloudformation-templates-using-iam-access-analyzer/)
 *
 * @param node the CfnResource to check
 */
export default Object.defineProperty(
  (node: CfnResource): NagRuleCompliance => {
    if (node instanceof CfnKey) {
      if (isCompliantPolicy(node)) {
        return NagRuleCompliance.COMPLIANT;
      }
      return NagRuleCompliance.NON_COMPLIANT;
    } else {
      return NagRuleCompliance.NOT_APPLICABLE;
    }
  },
  'name',
  { value: parse(__filename).name }
);

/**
 * Evalulate the KMS key policy for compliance
 *
 * @param node the CfnResource to check
 */
function isCompliantPolicy(node: any): boolean {
  const policy_document = Stack.of(node).resolve(node.keyPolicy);
  for (const policyStatement of policy_document.Statement ?? []) {
    if (
      effectIsAllow(node, policyStatement) &&
      principalIsStar(node, policyStatement)
    ) {
      if (NotMitigatedByAnyHighConfidenceCondition(node, policyStatement)) {
        return false;
      }
    }
  }
  return true;
}

/**
 * Evalulate if a KMS Key policy statement with * in Principal has any one common mitigation via a enumerated IAM condition key and operator pair
 *
 * @param node the CfnResource to check
 * @param policyStatement the policy statement to check
 */
function NotMitigatedByAnyHighConfidenceCondition(
  node: any,
  policyStatement: PolicyStatement
): boolean {
  var result = true;
  commonMitigatingConditions.forEach((mitigation) => {
    if (
      isMitigatedByCondition(
        node,
        policyStatement,
        mitigation.conditionKey,
        mitigation.conditionOperator,
        mitigation.WildcardInKeyValueIsNonCompliant
      )
    ) {
      result = false;
    }
  });

  return result;
}

/**
 * Evalulate if a KMS Key policy statement has 'Effect' equal to 'Allow'
 *
 * @param node the CfnResource to check
 * @param policyStatement the policy statement to check
 */
function effectIsAllow(node: any, policyStatement: PolicyStatement): boolean {
  const resolvedStatement = Stack.of(node).resolve(policyStatement);
  if (resolvedStatement.Effect === 'Allow') {
    return true;
  }
  return false;
}

/**
 * Evalulate if a KMS Key policy statement has '*' in Principal
 *
 * @param node the CfnResource to check
 * @param policyStatement the policy statement to check
 */
function principalIsStar(node: any, policyStatement: PolicyStatement): boolean {
  const principals = Stack.of(node).resolve(policyStatement).Principal;

  if (principals === '*') {
    return true;
  }
  const awsPrincipal = principals.AWS;
  if (Array.isArray(awsPrincipal)) {
    for (const account of awsPrincipal) {
      if (account === '*') {
        return true;
      }
    }
  } else if (awsPrincipal === '*') {
    return true;
  }
  return false;
}

/**
 * Evalulate if a KMS Key policy statement with * in Principal has any one common mitigation via a enumerated IAM Condtion and operator pair
 *
 * @param node the CfnResource to check
 * @param policyStatement the policy statement to check
 * @param conditionKey the mitigations key (e.g. aws:PrincipalOrgId)
 * @param conditionOperator the mitigations operator (e.g. StringEquals)
 * @param WildcardInKeyValueIsNonCompliant whether or not a wildcard in the specfied key's value is considered non-compliant
 */
function isMitigatedByCondition(
  node: any,
  policyStatement: PolicyStatement,
  conditionKey: string,
  conditionOperator: string,
  WildcardInKeyValueIsNonCompliant: boolean
): boolean {
  const resolvedStatement = Stack.of(node).resolve(policyStatement);
  const ConditionCheck =
    resolvedStatement?.Condition?.[conditionOperator]?.[conditionKey];
  if (ConditionCheck === undefined) {
    return false;
  }
  if (WildcardInKeyValueIsNonCompliant) {
    if (Array.isArray(ConditionCheck)) {
      const containsWildcard = ConditionCheck.some((element) => {
        if (element.includes('*')) {
          return true;
        }
        return false;
      });
      if (containsWildcard) {
        return false;
      }
    } else if (ConditionCheck.includes('*')) {
      return false;
    }
  }
  return true;
}
