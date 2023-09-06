import { MailerOptions, MailerOptionsFactory } from '@nestjs-modules/mailer';
import { EjsAdapter } from '@nestjs-modules/mailer/dist/adapters/ejs.adapter';
import { Injectable } from '@nestjs/common';
import config from './config.js';

@Injectable()
export class MailerConfigService implements MailerOptionsFactory {
  private MAIL_TRANSPORT = config.MAIL_TRANSPORT;
  private MAIL_FROM_NAME = config.MAIL_FROM_NAME;
  private MAIL_ADDRESS = this.MAIL_TRANSPORT.split(':')[1].split('//')[1];

  createMailerOptions(): MailerOptions {
    return {
      transport: this.MAIL_TRANSPORT,
      defaults: {
        from: `"${this.MAIL_FROM_NAME}" <${this.MAIL_ADDRESS}>`,
      },
      template: {
        adapter: new EjsAdapter(),
        options: {
          strict: false,
        },
      },
    };
  }
}
