import nodemailer from 'nodemailer';
import { z } from 'zod';

export interface VerificationMailer { sendVerification(to: string, link: string): Promise<void>; sendPasswordReset(to: string, link: string): Promise<void> }
const mailSchema=z.object({
  EMAIL_MODE:z.enum(['disabled','smtp']).default('disabled'),
  SMTP_HOST:z.string().max(253).default(''),
  SMTP_PORT:z.coerce.number().int().min(1).max(65535).default(587),
  SMTP_TLS_MODE:z.enum(['implicit','starttls']).default('starttls'),
  SMTP_USER:z.string().max(320).default(''),
  SMTP_PASSWORD:z.string().max(1024).default(''),
  SMTP_FROM:z.string().max(254).default(''),
});
export function createMailer(env:NodeJS.ProcessEnv):VerificationMailer|null {
  const parsed=mailSchema.safeParse(env);
  if(!parsed.success)throw new Error('Invalid SMTP configuration');
  const c=parsed.data;
  if(c.EMAIL_MODE==='disabled')return null;
  if(!/^[a-zA-Z0-9.-]+$/.test(c.SMTP_HOST)||!c.SMTP_USER||!c.SMTP_PASSWORD||!z.string().email().safeParse(c.SMTP_FROM).success)throw new Error('Invalid SMTP configuration');
  const transport=nodemailer.createTransport({
    host:c.SMTP_HOST,port:c.SMTP_PORT,secure:c.SMTP_TLS_MODE==='implicit',
    requireTLS:c.SMTP_TLS_MODE==='starttls',auth:{user:c.SMTP_USER,pass:c.SMTP_PASSWORD},
    tls:{rejectUnauthorized:true},connectionTimeout:10000,greetingTimeout:10000,socketTimeout:15000,
    logger:false,debug:false,disableFileAccess:true,disableUrlAccess:true,
  });
  return {async sendVerification(to,link){
    await transport.sendMail({from:c.SMTP_FROM,to,subject:'Подтвердите адрес для «Собрались!»',
      text:`Чтобы завершить регистрацию, откройте ссылку и самостоятельно задайте пароль:\n\n${link}\n\nСсылка действует 30 минут. Если вы не регистрировались, просто проигнорируйте это письмо.`,
      disableFileAccess:true,disableUrlAccess:true});
  },async sendPasswordReset(to,link){
    await transport.sendMail({from:c.SMTP_FROM,to,subject:'Восстановление доступа к «Собрались!»',
      text:`Чтобы задать новый пароль, откройте ссылку:\n\n${link}\n\nСсылка действует 30 минут. Если вы не запрашивали восстановление, проигнорируйте письмо: текущий пароль продолжит работать.`,
      disableFileAccess:true,disableUrlAccess:true});
  }};
}
