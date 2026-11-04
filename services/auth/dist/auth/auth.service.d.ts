export declare class AuthService {
    private readonly privateKey;
    login(username: string, password: string): Promise<{
        userId: number;
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }>;
    refresh(refreshToken: string): Promise<{
        userId: number;
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }>;
    logout(refreshToken: string): Promise<void>;
    private issueTokens;
}
