import { Controller, Get, Query } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) { }

  @Get()
  async getHello(
    @Query('after') after: number,
    @Query('take') take: number,
    @Query('q') query: string
  ): Promise<any[]> {
    return this.appService.getHello(
      take ? Number(take) : undefined,
      after ? Number(after) : undefined,
      query || ""
    );
  }
}
