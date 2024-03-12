import { buildClient, CommitmentPolicy, KmsKeyringNode } from '@aws-crypto/client-node';
import { toByteArray } from 'base64-js';
import { CustomEmailSenderTriggerEvent } from 'aws-lambda';
import { StringMap } from 'aws-lambda/trigger/cognito-user-pool-trigger/_common';

const getPlainTextCode = async (event: CustomEmailSenderTriggerEvent) => {
    if (!event.request.code) {
        throw Error('Could not find code');
    }

    if (!process.env.KEY_ID) {
        throw Error('Cannot decrypt code');
    }

    const client = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT);
    const generatorKeyId = process.env.KEY_ALIAS;
    const keyIds = [process.env.KEY_ID];
    const keyring = new KmsKeyringNode({ generatorKeyId, keyIds });

    const decryptOutput = await client.decrypt(keyring, toByteArray(event.request.code));

    const plainTextCode = decryptOutput.plaintext.toString();

    return plainTextCode;
}

const generateMessageToSend = async (event: CustomEmailSenderTriggerEvent, plainTextCode: String, toEmail: String) => {

    // 'CustomMessage_SignUp'
    // 'CustomMessage_AdminCreateUser'
    // 'CustomMessage_ResendCode'
    // 'CustomMessage_ForgotPassword'
    // 'CustomMessage_UpdateUserAttribute'
    // 'CustomMessage_VerifyUserAttribute'
    // 'CustomMessage_Authentication'

    if (event.triggerSource == 'CustomEmailSender_AdminCreateUser') {
        console.info(`Sending sign up email to ${toEmail}`);
    } else if (event.triggerSource == 'CustomEmailSender_ForgotPassword') {
        console.info(`Sending forgotten password email to ${toEmail} along with code ${plainTextCode}`);
    } else {
        console.info(`Unhandled event type: ${event.triggerSource}`);
        return;
    }

}

const handler = async (event: CustomEmailSenderTriggerEvent) => {
    console.info(`Event: ${JSON.stringify(event)}`);

    const plainTextCode = await getPlainTextCode(event);

    console.info(`Code or temporary password: ${JSON.stringify(plainTextCode)}`);

    const toEmail = (event.request.userAttributes as StringMap)['email'];

    await generateMessageToSend(event, plainTextCode, toEmail);

}

export { handler };
