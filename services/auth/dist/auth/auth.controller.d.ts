import { AuthService } from './auth.service';
export declare class AuthController {
    private readonly auth;
    constructor(auth: AuthService);
    login(body: {
        username: string;
        password: string;
    }): Promise<{
        userId: number;
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }>;
    refresh(body: {
        refreshToken: string;
    }): Promise<{
        userId: number;
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }>;
    logout(body: {
        refreshToken: string;
    }): Promise<void>;
}
