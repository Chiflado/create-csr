import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs/src/common';
import * as moment from 'moment';
import Certificate from 'pkijs/src/Certificate';
import Extension from 'pkijs/src/Extension';
import AttributeTypeAndValue from 'pkijs/src/AttributeTypeAndValue';
import Attribute from 'pkijs/src/Attribute';
import Extensions from 'pkijs/src/Extensions';
import CertificationRequest from 'pkijs/src/CertificationRequest';

export interface CreateCertificateParams {
  email: string;
  organization: string;
  organizationUnit: string;
}

export function createCertificate(params: CreateCertificateParams) {

  let certificateBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CERT
  let pkcs10Buffer = new ArrayBuffer(0);
  const trustedCertificates = []; // Array of root certificates from 'CA Bundle'

  const response = {
    request: '',
    cert: '',
    key: '',
    rawRequest: ''
  };

  const pkcs10 = new CertificationRequest();

  const hashAlg = 'SHA-1';
  const signAlg = 'RSASSA-PKCS1-v1_5';

// region Initial variables
  let sequence = new Promise<any>((resolve, reject) => {
    resolve();
});

  const certificate = new Certificate();

  let publicKey;
  let privateKey;
// endregion

// region Get a 'crypto' extension
  // tslint:disable-next-line:no-shadowed-variable
  const crypto = pkijs.getCrypto();
  if (typeof crypto === 'undefined') {
    alert('No WebCrypto extension found');
    return;
  }
  // endregion

  // set Certificate request params
  pkcs10.version = 0;
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.11', // Organization Unit name
    value: new asn1js.Utf8String({ value: params.organizationUnit })
  }));
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.10', // Organization name
    value: new asn1js.Utf8String({ value: params.organization })
  }));
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.3', // Common name
    value: new asn1js.Utf8String({ value: params.email })
  }));
  // endregion

  // set CSR params
  certificate.version = 0;
  certificate.serialNumber = new asn1js.Integer({ value: 1 });
  certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.11', // Organization Unit name
    value: new asn1js.Utf8String({ value: params.organizationUnit })
  }));
  certificate.issuer.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.10', // Organization name
    value: new asn1js.Utf8String({ value: params.organization })
  }));
  certificate.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.3', // Common name
    value: new asn1js.Utf8String({ value: params.email })
  }));

  // set Certification valid date from current day's start to 20 years from now
  const now = new Date();
  certificate.notBefore.value = moment(now).startOf('day').toDate();
  certificate.notAfter.value = new Date(new Date().setFullYear(now.getFullYear() + 20));

  // endregion


  certificate.extensions = []; // Extensions are not a part of certificate by default, it's an optional array

  // endregion

  // region 'KeyUsage' extension
  const bitArray = new ArrayBuffer(1);
  const bitView = new Uint8Array(bitArray);

  // 1000 0000 - 0x80
  // tslint:disable-next-line:no-bitwise
  bitView[0] |= 0x80; // Key usage 'digitalSignature' flag
  const keyUsage = new asn1js.BitString({ valueHex: bitArray });

  certificate.extensions.push(new Extension({
    extnID: '2.5.29.15',
    critical: false,
    extnValue: keyUsage.toBER(false),
    parsedValue: keyUsage // Parsed value for well-known extensions
  }));
  // endregion
  // endregion

  // region Create a new key pair
  sequence = sequence.then(() => {
    // region Get default algorithm parameters for key generation
    // tslint:disable-next-line:no-shadowed-variable
    const algorithm = pkijs.getAlgorithmParameters(signAlg, 'generatekey');
    if ('hash' in algorithm.algorithm) {
      algorithm.algorithm.hash.name = hashAlg;
    }
    // endregion

    return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
  });
  // endregion

  // region Store new key in an interim variables
  sequence = sequence.then(keyPair => {
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  }, error => {
    alert(`Error during key generation: ${error}`);
  });
  // endregion

  // region Exporting public key into 'subjectPublicKeyInfo' value of certificate
  sequence = sequence.then(() =>
    certificate.subjectPublicKeyInfo.importKey(publicKey)
  );
  // endregion

    // region Exporting public key into 'subjectPublicKeyInfo' value of PKCS#10
  sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
  // endregion

  pkcs10.attributes = [];
  // region SubjectKeyIdentifier
  sequence = sequence.then(() => crypto.digest('SHA-1', pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex))
    .then(result => {
      pkcs10.attributes.push(new Attribute({
        type: '1.2.840.113549.1.9.14', // pkcs-9-at-extensionRequest
        values: [(new Extensions({
          extensions: [
            new Extension({
              extnID: '2.5.29.14',
              critical: false,
              extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
            })
          ]
        })).toSchema()]
      }));
    }
    );
  // endregion

  // region Signing final PKCS#10 request
  sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlg), error => Promise.reject(`Error during exporting public key: ${error}`));
  // endregion

  sequence.then(() => {
    pkcs10Buffer = pkcs10.toSchema().toBER(false);

    const certRequestString = String.fromCharCode.apply(null, new Uint8Array(pkcs10Buffer));

    let resultString = '-----BEGIN CERTIFICATE REQUEST-----\r\n';
    resultString = `${resultString}${formatPEM(window.btoa(certRequestString))}`;
    resultString = `${resultString}\r\n-----END CERTIFICATE REQUEST-----\r\n`;

    trustedCertificates.push(certificate);

    response.request = resultString;
    response.rawRequest = window.btoa(certRequestString);

  }, error => Promise.reject(`Error signing PKCS#10: ${error}`));

  // region Signing final certificate
  sequence = sequence.then(() =>
    certificate.sign(privateKey, hashAlg),
  error => {
    alert(`Error during exporting public key: ${error}`);
  });
  // endregion

  // region Encode and store certificate
  sequence = sequence.then(() => {
    certificateBuffer = certificate.toSchema(true).toBER(false);

    const certificateString = String.fromCharCode.apply(null, new Uint8Array(certificateBuffer));

    let resultString = '-----BEGIN CERTIFICATE-----\r\n';
    resultString = `${resultString}${formatPEM(window.btoa(certificateString))}`;
    resultString = `${resultString}\r\n-----END CERTIFICATE-----\r\n`;

    response.cert = resultString;
  }, error => {
    alert(`Error during signing: ${error}`);
  });
  // endregion

  // region Exporting private key
  sequence = sequence.then(() =>
    crypto.exportKey('pkcs8', privateKey)
  );
  // endregion

  // region Store exported key on Web page
  sequence = sequence.then(result => {
    // noinspection JSCheckFunctionSignatures
    const privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));

    let resultString = '';

    resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
    resultString = `${resultString}${formatPEM(window.btoa(privateKeyString))}`;
    resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

    response.key = resultString;
  }, error => {
    alert(`Error during exporting of private key: ${error}`);
  });
  // endregion
  return response;
}
// *********************************************************************************
// endregion

// *********************************************************************************
// region Auxiliary functions
// *********************************************************************************
function formatPEM(pemString) {
  const stringLength = pemString.length;
  let resultString = '';

  for (let i = 0, count = 0; i < stringLength; i++, count++) {
    if (count > 63) {
      resultString = `${resultString}\r\n`;
      count = 0;
    }

    resultString = `${resultString}${pemString[i]}`;
  }

  return resultString;
}
