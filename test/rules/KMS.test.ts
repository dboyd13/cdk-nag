/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
import {
  Effect,
  PolicyStatement,
  AnyPrincipal,
  PolicyDocument,
  AccountPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Key, KeySpec } from 'aws-cdk-lib/aws-kms';
import { Aspects, Stack } from 'aws-cdk-lib/core';
import {
  KMSBackingKeyRotationEnabled,
  KMSKeyPublicAccessProhibited,
} from '../../src/rules/kms';
import { validateStack, TestType, TestPack } from './utils';

const testPack = new TestPack([
  KMSBackingKeyRotationEnabled,
  KMSKeyPublicAccessProhibited,
]);
let stack: Stack;

beforeEach(() => {
  stack = new Stack();
  Aspects.of(stack).add(testPack);
});

describe('AWS Key Management Service (KMS)', () => {
  describe('KMSBackingKeyRotationEnabled: KMS Symmetric keys have automatic key rotation enabled', () => {
    const ruleId = 'KMSBackingKeyRotationEnabled';
    test('Noncompliance 1', () => {
      new Key(stack, 'rSymmetricKey');
      validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
    });
    test('Compliance', () => {
      new Key(stack, 'rSymmetricKey', { enableKeyRotation: true });
      new Key(stack, 'rAsymmetricKey', { keySpec: KeySpec.RSA_4096 });
      validateStack(stack, ruleId, TestType.COMPLIANCE);
    });
  });
  describe('KMSKeyPublicAccessProhibited', () => {
    const ruleId = 'KMSKeyPublicAccessProhibited';

    describe('Simple tests', () => {
      test('Compliance 1 - Default key policy', () => {
        new Key(stack, 'rSymmetricKey');
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Compliance 2 - Statements: 1, Effect: Deny, Principal: *, Conditions: none', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.DENY,
              actions: ['*'],
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Compliance 3 - Statements: 1, Effect: Allow, Principal: AccountPrincipal, Conditions: none', () => {
        const KeyPolicy = {
          Version: '2012-10-17',
          Id: 'DefaultKeyPolicy',
          Statement: [
            {
              Sid: 'Enable IAM User Permissions',
              Effect: 'Allow',
              Principal: {
                AWS: 'arn:aws:iam::12345678910:root',
              },
              Action: 'kms:*',
              Resource: '*',
            },
          ],
        };

        new Key(stack, 'rSymmetricKey', {
          policy: PolicyDocument.fromJson(KeyPolicy),
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Noncompliance 1 - Statements: 1, Effect: Allow, Principal: *, Conditions: none', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });

      test('Noncompliance 2 - Statements: 1, Effect: Allow, Principal: [AccountPrincipal,*], Conditions: none', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              principals: [
                new AccountPrincipal('123456789012'),
                new AnyPrincipal(),
              ],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });

      test('Noncompliance 3 - Statements: 2, Effect: Allow | Allow, Principal: AccountPrincipal | *, Conditions: none', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              principals: [new AccountPrincipal('123456789012')],
              resources: ['*'],
            }),
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });
    });

    describe('PrincipalOrgId tests', () => {
      test('Compliance 1 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalOrgId, Condition operator: StringEquals', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringEquals: {
                  'aws:PrincipalOrgId': 'any-value',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Compliance 2 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalOrgId, Condition operator: StringEqualsIgnoreCase', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringEqualsIgnoreCase: {
                  'aws:PrincipalOrgId': 'any-value',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Compliance 3 - Statements: 1, Effect: Allow, Principal: AccountPrincipal, Condition key: aws:PrincipalOrgId, Condition operator: StringLike', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringLike: {
                  'aws:PrincipalOrgId': 'any-value',
                },
              },
              principals: [new AccountPrincipal('123456789012')],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });

      test('Noncompliance 1 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalOrgId, Condition operator: StringLike', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringLike: {
                  'aws:PrincipalOrgId': 'any-value',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });

      test('Noncompliance 2 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalOrgId, Condition operator: StringNotEquals', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringNotEquals: {
                  'aws:PrincipalOrgId': 'any-value',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });
    });

    describe('PrincipalArn tests', () => {
      test('Compliance 1 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalArn, Condition operator: StringEquals, Condition value: string', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringEquals: {
                  'aws:PrincipalArn': 'arn:aws:iam::12345678910:user',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });
      test('Compliance 2 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalArn, Condition operator: StringEqualsIgnoreCase, Condition value: array of strings', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringEqualsIgnoreCase: {
                  'aws:PrincipalArn': [
                    'arn:aws:iam::12345678910:user1',
                    'arn:aws:iam::12345678910:user2',
                  ],
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });
      test('Compliance 3 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalArn, Condition operator: StringEqualsIgnoreCase, Condition value: string', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                StringEqualsIgnoreCase: {
                  'aws:PrincipalArn': 'arn:aws:iam::12345678910:user',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.COMPLIANCE);
      });
      test('Noncompliance 1 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalArn, Condition operator: ArnEqual, Condition value: wildcard in string', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                ArnEqual: {
                  'aws:PrincipalArn': 'arn:aws:iam::*:user',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });
      test('Noncompliance 2 - Statements: 1, Effect: Allow, Principal: *, Condition key: aws:PrincipalArn, Condition operator: ArnLike, Condition value: wildcard in string', () => {
        const KeyPolicy = new PolicyDocument({
          statements: [
            new PolicyStatement({
              effect: Effect.ALLOW,
              actions: ['kms:Encrypt', 'kms:Decrypt'],
              conditions: {
                ArnLike: {
                  'aws:PrincipalArn': 'arn:aws:iam::*:user',
                },
              },
              principals: [new AnyPrincipal()],
              resources: ['*'],
            }),
          ],
        });
        new Key(stack, 'rSymmetricKey', {
          policy: KeyPolicy,
        });
        validateStack(stack, ruleId, TestType.NON_COMPLIANCE);
      });
    });
  });
});
