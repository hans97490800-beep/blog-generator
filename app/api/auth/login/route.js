import { NextResponse } from 'next/server';
import { verifyPassword, createToken } from '@/app/lib/auth';
import { get } from '@/app/lib/db';
import { cookies } from 'next/headers';

export async function POST(request) {
    try {
        const body = await request.json();
        const { email, password } = body;

        if (!email || !password) {
            return NextResponse.json({ error: '이메일과 비밀번호를 입력하세요.' }, { status: 400 });
        }

        const user = await get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return NextResponse.json({ error: '사용자를 찾을 수 없습니다.' }, { status: 401 });
        }

        const isValid = await verifyPassword(password, user.password);
        if (!isValid) {
            return NextResponse.json({ error: '비밀번호가 일치하지 않습니다.' }, { status: 401 });
        }

        const token = await createToken(user.id);
        const cookieStore = await cookies();
        cookieStore.set('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7, // 1 week
            path: '/',
        });

        return NextResponse.json({
            message: '로그인 성공',
            user: { id: user.id, email: user.email, name: user.name },
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        return NextResponse.json({ error: '로그인 실패' }, { status: 500 });
    }
}
