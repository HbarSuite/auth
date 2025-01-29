import { Test, TestingModule } from '@nestjs/testing'
import { TwoFactoryAuthController } from './2fa.controller'
import { TwoFactoryAuthService } from './2fa.service'

/**
 * Test suite for TwoFactoryAuthController
 * 
 * @description
 * Contains unit tests for verifying the functionality of the TwoFactoryAuthController,
 * which handles Two-Factor Authentication (2FA) related endpoints and operations.
 * 
 * @group Unit Tests
 * @group Controllers
 */
describe('2faController', () => {
  let controller: TwoFactoryAuthController;

  /**
   * Test setup before each test case
   * 
   * @description
   * Creates a testing module with TwoFactoryAuthController and its dependencies.
   * Initializes the controller instance for testing.
   */
  beforeEach(async () => {
    // Create testing module with required controllers and providers
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TwoFactoryAuthController],
      providers: [TwoFactoryAuthService],
    }).compile();

    // Get controller instance for testing
    controller = module.get<TwoFactoryAuthController>(TwoFactoryAuthController);
  });

  /**
   * Test to verify controller instantiation
   * 
   * @description
   * Ensures that the TwoFactoryAuthController is properly instantiated
   * and defined with all required dependencies.
   */
  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
