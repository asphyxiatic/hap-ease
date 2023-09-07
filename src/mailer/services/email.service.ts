import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { join } from 'path';
import { TemplatesEnum } from '../enums/templates.enum.js';
import { TemplatesDiscriptionEnum } from '../enums/templates-discription.enum.js';

@Injectable()
export class EmailService {
  private readonly TEMPLATES_PATH = '../mail-templates';

  constructor(private readonly mailerService: MailerService) {}

  public async sendTemplete(
    email: string,
    template: TemplatesEnum,
    templateDiscription: TemplatesDiscriptionEnum,
    context: { [key: string]: any },
  ) {
    this.mailerService
      .sendMail({
        to: email,
        subject: templateDiscription,
        template: join(__dirname, this.TEMPLATES_PATH, template),
        context: context,
      })
      .catch((error: any) => {
        throw new InternalServerErrorException('🚨 failed to send message!');
      });
  }
}