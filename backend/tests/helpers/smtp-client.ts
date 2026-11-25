// Isolated child: NODE_EXTRA_CA_CERTS must be configured before Node starts.
import {createMailer} from '../../src/mail.js';
const mailer=createMailer(process.env);if(!mailer)throw Error('Synthetic SMTP is disabled');
try{
 await mailer.sendVerification('synthetic@example.test','https://test.invalid/verify-email#'+'A'.repeat(43));
 await mailer.sendPasswordReset('synthetic@example.test','https://test.invalid/reset-password#'+'B'.repeat(43));
 if(process.env.EXPECT_REJECT==='yes')process.exit(1);
}catch{
 if(process.env.EXPECT_REJECT!=='yes')process.exit(1);
}
