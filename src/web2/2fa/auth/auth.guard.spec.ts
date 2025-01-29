import { Test, TestingModule } from '@nestjs/testing';
import { TwoFactoryAuthGuard } from './auth.guard'

describe('TwoFactoryAuthGuard', () => {
  let guard: TwoFactoryAuthGuard;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TwoFactoryAuthGuard],
    }).compile();

    guard = module.get<TwoFactoryAuthGuard>(TwoFactoryAuthGuard);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should allow access by default', async () => {
    expect(await guard.canActivate(null)).toBe(true);
  });
});
